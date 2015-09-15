/*
 * histogram-based function tracer
 *
 * Copyright (C) 2015 Tom Zanussi <tom.zanussi@linux.intel.com>
 *
 * Based on code from the function_tracer, that is:
 *
 * Copyright (C) 2007-2008 Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2008 Ingo Molnar <mingo@redhat.com>
 */
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/slab.h>

#include "tracing_map.h"
#include "trace.h"

static void tracing_start_function_hist(struct trace_array *tr);
static void tracing_stop_function_hist(struct trace_array *tr);
static void
function_hist_call(unsigned long ip, unsigned long parent_ip,
		   struct ftrace_ops *op, struct pt_regs *pt_regs);

enum hist_key_flags {
	HIST_FIELD_SYM		= 1,
	HIST_FIELD_HEX		= 2,
};

struct function_hist_data {
	atomic64_t			total_hits;
	atomic64_t			drops;
	unsigned long			key_flags;
	struct tracing_map_sort_key	sort_key;
	struct tracing_map		*map;
};

#define FUNCTION_HIST_BITS_DEFAULT	16
#define HITCOUNT_IDX			0

static struct function_hist_data *function_hist_data;

static int allocate_ftrace_ops(struct trace_array *tr)
{
	struct ftrace_ops *ops;

	ops = kzalloc(sizeof(*ops), GFP_KERNEL);
	if (!ops)
		return -ENOMEM;

	ops->func = function_hist_call;
	ops->flags = FTRACE_OPS_FL_RECURSION_SAFE;

	tr->ops = ops;
	ops->private = tr;

	return 0;
}

static int function_hist_init(struct trace_array *tr)
{
	ftrace_func_t func;

	/*
	 * Instance trace_arrays get their ops allocated
	 * at instance creation. Unless it failed
	 * the allocation.
	 */
	if (!tr->ops)
		return -ENOMEM;

	func = function_hist_call;

	ftrace_init_array_ops(tr, func);

	tracing_start_function_hist(tr);

	return 0;
}

static void function_hist_reset(struct trace_array *tr)
{
	tracing_stop_function_hist(tr);
	ftrace_reset_array_ops(tr);
}

static void
function_hist_call(unsigned long ip, unsigned long parent_ip,
		   struct ftrace_ops *op, struct pt_regs *pt_regs)
{
	struct trace_array *tr = op->private;
	struct tracing_map_elt *elt;
	void *key;
	int bit;

	if (unlikely(!tr->function_enabled))
		return;

	preempt_disable_notrace();

	bit = trace_test_and_set_recursion(TRACE_FTRACE_START,
					   TRACE_FTRACE_MAX);
	if (bit < 0)
		goto out;

	if (atomic64_read(&function_hist_data->drops)) {
		atomic64_inc(&function_hist_data->drops);
		goto out_clear;
	}

	key = (void *)&ip;
	elt = tracing_map_insert(function_hist_data->map, key);
	if (elt)
		tracing_map_update_sum(elt, HITCOUNT_IDX, 1);
	else
		atomic64_inc(&function_hist_data->drops);

	atomic64_inc(&function_hist_data->total_hits);
 out_clear:
	trace_clear_recursion(bit);
 out:
	preempt_enable_notrace();
}

static void destroy_hist_data(struct function_hist_data *hist_data)
{
	tracing_map_destroy(hist_data->map);
	kfree(hist_data);
}

static inline void create_sort_key(struct function_hist_data *hist_data)
{
	hist_data->sort_key.field_idx = HITCOUNT_IDX;
	hist_data->sort_key.descending = false;
}

static int create_tracing_map_fields(struct function_hist_data *hist_data)
{
	struct tracing_map *map = hist_data->map;
	unsigned int idx;

	idx = tracing_map_add_sum_field(map);
	if (idx < 0)
		return idx;

	idx = tracing_map_add_key_field(map, 0, tracing_map_cmp_none);
	if (idx < 0)
		return idx;

	return 0;
}

static struct function_hist_data *create_hist_data(unsigned int map_bits)
{
	struct function_hist_data *hist_data;
	unsigned int key_size;
	int ret = 0;

	hist_data = kzalloc(sizeof(*hist_data), GFP_KERNEL);
	if (!hist_data)
		return NULL;

	create_sort_key(hist_data);

	key_size = sizeof(unsigned long); /* ip */
	hist_data->map = tracing_map_create(map_bits, key_size,
					    NULL, hist_data);
	if (IS_ERR(hist_data->map)) {
		ret = PTR_ERR(hist_data->map);
		hist_data->map = NULL;
		goto free;
	}

	ret = create_tracing_map_fields(hist_data);
	if (ret)
		goto free;

	ret = tracing_map_init(hist_data->map);
	if (ret)
		goto free;
 out:
	return hist_data;
 free:
	destroy_hist_data(hist_data);
	if (ret)
		hist_data = ERR_PTR(ret);
	else
		hist_data = NULL;

	goto out;
}

static void tracing_start_function_hist(struct trace_array *tr)
{
	unsigned int hist_trigger_bits = FUNCTION_HIST_BITS_DEFAULT;
	struct function_hist_data *hist_data;

	if (function_hist_data) {
		destroy_hist_data(function_hist_data);
		function_hist_data = NULL;
	}

	hist_data = create_hist_data(hist_trigger_bits);
	if (IS_ERR(hist_data))
		return;

	hist_data->key_flags |= HIST_FIELD_SYM;

	function_hist_data = hist_data;

	tr->function_enabled = 0;
	register_ftrace_function(tr->ops);
	tr->function_enabled = 1;
}

static void tracing_stop_function_hist(struct trace_array *tr)
{
	tr->function_enabled = 0;
	unregister_ftrace_function(tr->ops);
}

static void function_hist_entry_print(struct seq_file *m,
				      struct function_hist_data *hist_data,
				      void *key, struct tracing_map_elt *elt)
{
	char str[KSYM_SYMBOL_LEN];
	unsigned long uval;

	if (hist_data->key_flags & HIST_FIELD_SYM) {
		uval = *(unsigned long *)key;
		kallsyms_lookup(uval, NULL, NULL, NULL, str);
		seq_printf(m, "ip: [%lx] %-35s", uval, str);
	} else if (hist_data->key_flags & HIST_FIELD_HEX) {
		uval = *(unsigned long *)key;
		seq_printf(m, "ip: %lx", uval);
	} else {
		uval = *(unsigned long *)key;
		seq_printf(m, "ip: %10lu", uval);
	}

	seq_printf(m, " hitcount: %10llu",
		   tracing_map_read_sum(elt, HITCOUNT_IDX));

	seq_puts(m, "\n");
}

static int print_entries(struct seq_file *m,
			 struct function_hist_data *hist_data)
{
	struct tracing_map_sort_entry **sort_entries = NULL;
	struct tracing_map *map = hist_data->map;
	unsigned int i, n_entries;

	n_entries = tracing_map_sort_entries(map, &hist_data->sort_key, 1,
					     &sort_entries);
	if (n_entries < 0)
		return n_entries;

	for (i = 0; i < n_entries; i++)
		function_hist_entry_print(m, hist_data,
					  sort_entries[i]->key,
					  sort_entries[i]->elt);

	tracing_map_destroy_sort_entries(sort_entries, n_entries);

	return n_entries;
}

static int hist_show(struct seq_file *m, void *v)
{
	int n_entries, ret = 0;

	mutex_lock(&trace_types_lock);

	if (!function_hist_data)
		goto out_unlock;

	n_entries = print_entries(m, function_hist_data);
	if (n_entries < 0) {
		ret = n_entries;
		n_entries = 0;
	}

	seq_printf(m, "\nTotals:\n    Hits: %llu\n    Entries: %u\n    Dropped: %llu\n",
		   (u64)atomic64_read(&function_hist_data->total_hits),
		   n_entries, (u64)atomic64_read(&function_hist_data->drops));
 out_unlock:
	mutex_unlock(&trace_types_lock);

	return ret;
}

static int function_hist_open(struct inode *inode, struct file *file)
{
	return single_open(file, hist_show, file);
}

const struct file_operations function_hist_fops = {
	.open = function_hist_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int ftrace_create_function_hist_files(struct trace_array *tr,
				      struct dentry *parent)
{
	struct dentry *d_tracer;
	int ret;

	d_tracer = tracing_init_dentry();
	if (IS_ERR(d_tracer))
		return 0;

	trace_create_file("function_hist", 0444, d_tracer,
			NULL, &function_hist_fops);

	ret = allocate_ftrace_ops(tr);
	if (ret)
		return ret;

	return 0;
}

void ftrace_destroy_function_hist_files(struct trace_array *tr)
{
	kfree(tr->ops);
	tr->ops = NULL;
}

static struct tracer function_hist __tracer_data = {
	.name		= "function_hist",
	.init		= function_hist_init,
	.reset		= function_hist_reset,
	.allow_instances = true,
#ifdef CONFIG_FTRACE_SELFTEST
	.selftest	= trace_selftest_startup_function,
#endif
};

static __init int init_function_hist(void)
{
	return register_tracer(&function_hist);
}
fs_initcall(init_function_hist);
