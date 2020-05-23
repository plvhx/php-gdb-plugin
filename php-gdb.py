# GDB plugin for debugging PHP engine
# 2020 @ Paulus Gandung Prakosa <gandung@ppp.cylab.cmu.edu>

import gdb

def arg_to_num(arg):
	if arg.startswith('0x'):
		v = int(arg, 0x10)
	else:
		v = int(arg, 0x0a)
	return v

class PHPArray(gdb.Command):
	def __init__(self):
		super(PHPArray, self).__init__("php-array", gdb.COMMAND_USER)

	def get_gc_refcount(self, addr):
		refcount = gdb.execute(
			"p (*(zend_array *)((*(zval *)({})).value.arr)).gc.refcount".format(hex(addr)),
			to_string=True
		)

		return refcount.split(' = ')[1].rstrip("\n")

	def get_gc_typeinfo(self, addr):
		typeinfo = gdb.execute(
			"p (*(zend_array *)((*(zval *)({})).value.arr)).gc.u.type_info".format(hex(addr)),
			to_string=True
		)

		return typeinfo.split(' = ')[1].rstrip("\n")

	def get_uv_flags(self, addr):
		flags = gdb.execute(
			"p/d (*(zend_array *)((*(zval *)({})).value.arr)).u.v.flags".format(hex(addr)),
			to_string=True
		)

		return flags.split(' = ')[1].rstrip("\n")

	def get_uv_unused_(self, addr):
		unused_ = gdb.execute(
			"p/d (*(zend_array *)((*(zval *)({})).value.arr)).u.v._unused".format(hex(addr)),
			to_string=True
		)

		return unused_.split(' = ')[1].rstrip("\n")

	def get_uv_n_iterators_count(self, addr):
		n_iterators_count = gdb.execute(
			"p/d (*(zend_array *)((*(zval *)({})).value.arr)).u.v.nIteratorsCount".format(hex(addr)),
			to_string=True
		)

		return n_iterators_count.split(' = ')[1].rstrip("\n")

	def get_uv_unused2_(self, addr):
		unused2_ = gdb.execute(
			"p/d (*(zend_array *)((*(zval *)({})).value.arr)).u.v._unused2".format(hex(addr)),
			to_string=True
		)

		return unused2_.split(' = ')[1].rstrip("\n")

	def get_n_table_mask(self, addr):
		n_table_mask = gdb.execute(
			"p/u (*(zend_array *)((*(zval *)({})).value.arr)).nTableMask".format(hex(addr)),
			to_string=True
		)

		return n_table_mask.split(' = ')[1].rstrip("\n")

	def get_ardata(self, addr):
		ar_data = gdb.execute(
			"p/x (*(zend_array *)((*(zval *)({})).value.arr)).arData".format(hex(addr)),
			to_string=True
		)

		return ar_data.split(' = ')[1].rstrip("\n")

	def get_n_num_used(self, addr):
		n_num_used = gdb.execute(
			"p/u (*(zend_array *)((*(zval *)({})).value.arr)).nNumUsed".format(hex(addr)),
			to_string=True
		)

		return n_num_used.split(' = ')[1].rstrip("\n")

	def get_n_num_of_elements(self, addr):
		n_num_of_elems = gdb.execute(
			"p/u (*(zend_array *)((*(zval *)({})).value.arr)).nNumOfElements".format(hex(addr)),
			to_string=True
		)

		return n_num_of_elems.split(' = ')[1].rstrip("\n")

	def get_n_table_size(self, addr):
		n_tab_sz = gdb.execute(
			"p/u (*(zend_array *)((*(zval *)({})).value.arr)).nTableSize".format(hex(addr)),
			to_string=True
		)

		return n_tab_sz.split(' = ')[1].rstrip("\n")

	def get_n_internal_pointer(self, addr):
		n_internal_ptr = gdb.execute(
			"p/u (*(zend_array *)((*(zval *)({})).value.arr)).nInternalPointer".format(hex(addr)),
			to_string=True
		)

		return n_internal_ptr.split(' = ')[1].rstrip("\n")

	def get_n_next_free_element(self, addr):
		n_next_free_elem = gdb.execute(
			"p/u (*(zend_array *)((*(zval *)({})).value.arr)).nNextFreeElement".format(hex(addr)),
			to_string=True
		)

		return n_next_free_elem.split(' = ')[1].rstrip("\n")

	def get_p_destructor(self, addr):
		p_destructor = gdb.execute(
			"p/x (*(zend_array *)((*(zval *)({})).value.arr)).pDestructor".format(hex(addr)),
			to_string=True
		)

		return p_destructor.split(' = ')[1].rstrip("\n")

	def invoke(self, arg, from_tty):
		print("- gc (zend_refcounted_h)")
		print("  - refcount (uint32_t): {}".format(self.get_gc_refcount(arg_to_num(arg))))
		print("  - u (union)")
		print("    - type_info: {}".format(self.get_gc_typeinfo(arg_to_num(arg))))
		print("- u (union)")
		print("  - flags (unsigned char): {}".format(self.get_uv_flags(arg_to_num(arg))))
		print("  - _unused (unsigned char): {}".format(self.get_uv_unused_(arg_to_num(arg))))
		print("  - nIteratorsCount (unsigned char): {}".format(self.get_uv_n_iterators_count(arg_to_num(arg))))
		print("  - _unused2 (unsigned char): {}".format(self.get_uv_unused2_(arg_to_num(arg))))
		print("- nTableMask (uint32_t): {}".format(self.get_n_table_mask(arg_to_num(arg))))
		print("- arData (Bucket *): {}".format(self.get_ardata(arg_to_num(arg))))
		print("- nNumUsed (uint32_t): {}".format(self.get_n_num_used(arg_to_num(arg))))
		print("- nNumOfElements (uint32_t): {}".format(self.get_n_num_of_elements(arg_to_num(arg))))
		print("- nTableSize (uint32_t): {}".format(self.get_n_table_size(arg_to_num(arg))))
		print("- nInternalPointer (uint32_t): {}".format(self.get_n_internal_pointer(arg_to_num(arg))))
		print("- nNextFreeElement (int64_t): {}".format(self.get_n_next_free_element(arg_to_num(arg))))
		print("- pDestructor (dtor_func_t): {}".format(self.get_p_destructor(arg_to_num(arg))))

class PHPHashTableBucket(gdb.Command):
	def __init__(self):
		super(PHPHashTableBucket, self).__init__("php-hashtab-bucket", gdb.COMMAND_USER)

	def get_zval_lval(self, addr):
		lval = gdb.execute(
			"p (*(Bucket *)({})).val.value.lval".format(hex(addr)),
			to_string=True
		)

		return lval.split(' = ')[1].rstrip("\n")

	def get_zval_dval(self, addr):
		dval = gdb.execute(
			"p (*(Bucket *)({})).val.value.dval".format(hex(addr)),
			to_string=True
		)

		return dval.split(' = ')[1].rstrip("\n")

	def get_zval_counted(self, addr):
		counted = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.counted".format(hex(addr)),
			to_string=True
		)

		return counted.split(' = ')[1].rstrip("\n")

	def get_zval_str(self, addr):
		tstr = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.str".format(hex(addr)),
			to_string=True
		)

		return tstr.split(' = ')[1].rstrip("\n")

	def get_zval_arr(self, addr):
		tarr = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.arr".format(hex(addr)),
			to_string=True
		)

		return tarr.split(' = ')[1].rstrip("\n")

	def get_zval_obj(self, addr):
		tobj = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.obj".format(hex(addr)),
			to_string=True
		)

		return tobj.split(' = ')[1].rstrip("\n")

	def get_zval_res(self, addr):
		tres = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.res".format(hex(addr)),
			to_string=True
		)

		return tres.split(' = ')[1].rstrip("\n")

	def get_zval_ref(self, addr):
		tref = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.ref".format(hex(addr)),
			to_string=True
		)

		return tref.split(' = ')[1].rstrip("\n")

	def get_zval_ast(self, addr):
		tast = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.ast".format(hex(addr)),
			to_string=True
		)

		return tast.split(' = ')[1].rstrip("\n")

	def get_zval_zv(self, addr):
		zv = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.zv".format(hex(addr)),
			to_string=True
		)

		return zv.split(' = ')[1].rstrip("\n")

	def get_zval_ptr(self, addr):
		ptr = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.ptr".format(hex(addr)),
			to_string=True
		)

		return ptr.split(' = ')[1].rstrip("\n")

	def get_zval_ce(self, addr):
		ce = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.ce".format(hex(addr)),
			to_string=True
		)

		return ce.split(' = ')[1].rstrip("\n")

	def get_zval_func(self, addr):
		fn = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.func".format(hex(addr)),
			to_string=True
		)

		return fn.split(' = ')[1].rstrip("\n")

	def get_zval_ww_w1(self, addr):
		w1 = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.ww.w1".format(hex(addr)),
			to_string=True
		)

		return w1.split(' = ')[1].rstrip("\n")

	def get_zval_ww_w2(self, addr):
		w2 = gdb.execute(
			"p/x (*(Bucket *)({})).val.value.ww.w2".format(hex(addr)),
			to_string=True
		)

		return w2.split(' = ')[1].rstrip("\n")

	def get_zval_u1_v_type(self, addr):
		vtype = gdb.execute(
			"p/d (*(Bucket *)({})).val.u1.v.type".format(hex(addr)),
			to_string=True
		)

		return vtype.split(' = ')[1].rstrip("\n")

	def get_zval_u1_v_type_flags(self, addr):
		type_flags = gdb.execute(
			"p/d (*(Bucket *)({})).val.u1.v.type_flags".format(hex(addr)),
			to_string=True
		)

		return type_flags.split(' = ')[1].rstrip("\n")

	def get_zval_u1_v_u_extra(self, addr):
		extra = gdb.execute(
			"p/d (*(Bucket *)({})).val.u1.v.u.extra".format(hex(addr)),
			to_string=True
		)

		return extra.split(' = ')[1].rstrip("\n")

	def get_zval_u1_type_info(self, addr):
		type_info = gdb.execute(
			"p/d (*(Bucket *)({})).val.u1.type_info".format(hex(addr)),
			to_string=True
		)

		return type_info.split(' = ')[1].rstrip("\n")

	def get_zval_u2_next(self, addr):
		tnext = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.next".format(hex(addr)),
			to_string=True
		)

		return tnext.split(' = ')[1].rstrip("\n")

	def get_zval_u2_cache_slot(self, addr):
		cache_slot = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.cache_slot".format(hex(addr)),
			to_string=True
		)

		return cache_slot.split(' = ')[1].rstrip("\n")

	def get_zval_u2_opline_num(self, addr):
		opline_num = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.opline_num".format(hex(addr)),
			to_string=True
		)

		return opline_num.split(' = ')[1].rstrip("\n")

	def get_zval_u2_lineno(self, addr):
		lineno = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.lineno".format(hex(addr)),
			to_string=True
		)

		return lineno.split(' = ')[1].rstrip("\n")

	def get_zval_u2_num_args(self, addr):
		num_args = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.num_args".format(hex(addr)),
			to_string=True
		)

		return num_args.split(' = ')[1].rstrip("\n")

	def get_zval_u2_fe_pos(self, addr):
		fe_pos = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.fe_pos".format(hex(addr)),
			to_string=True
		)

		return fe_pos.split(' = ')[1].rstrip("\n")

	def get_zval_u2_fe_iter_idx(self, addr):
		fe_iter_idx = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.fe_iter_idx".format(hex(addr)),
			to_string=True
		)

		return fe_iter_idx.split(' = ')[1].rstrip("\n")

	def get_zval_u2_access_flags(self, addr):
		acc_flags = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.access_flags".format(hex(addr)),
			to_string=True
		)

		return acc_flags.split(' = ')[1].rstrip("\n")

	def get_zval_u2_property_guard(self, addr):
		prop_guard = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.property_guard".format(hex(addr)),
			to_string=True
		)

		return prop_guard.split(' = ')[1].rstrip("\n")

	def get_zval_u2_constant_flags(self, addr):
		const_flags = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.constant_flags".format(hex(addr)),
			to_string=True
		)

		return const_flags.split(' = ')[1].rstrip("\n")

	def get_zval_u2_extra(self, addr):
		extra = gdb.execute(
			"p/u (*(Bucket *)({})).val.u2.extra".format(hex(addr)),
			to_string=True
		)

		return extra.split(' = ')[1].rstrip("\n")

	def get_h(self, addr):
		h = gdb.execute(
			"p/lu (*(Bucket *)({})).h".format(hex(addr)),
			to_string=True
		)

		return h.split(' = ')[1].rstrip("\n")

	def get_key(self, addr):
		tkey = gdb.execute(
			"p/lx (*(Bucket *)({})).key".format(hex(addr)),
			to_string=True
		)

		return tkey.split(' = ')[1].rstrip("\n")

	def invoke(self, arg, from_tty):
		print("- val (zval)")
		print("  - value (zend_value)")
		print("    - lval (zend_long): {}".format(self.get_zval_lval(arg_to_num(arg))))
		print("    - dval (double): {}".format(self.get_zval_dval(arg_to_num(arg))))
		print("    - counted (zend_refcounted *): {}".format(self.get_zval_counted(arg_to_num(arg))))
		print("    - str (zend_string *): {}".format(self.get_zval_str(arg_to_num(arg))))
		print("    - arr (zend_array *): {}".format(self.get_zval_arr(arg_to_num(arg))))
		print("    - obj (zend_object *): {}".format(self.get_zval_obj(arg_to_num(arg))))
		print("    - res (zend_resource *): {}".format(self.get_zval_res(arg_to_num(arg))))
		print("    - ref (zend_reference *): {}".format(self.get_zval_ref(arg_to_num(arg))))
		print("    - ast (zend_ast_ref *): {}".format(self.get_zval_ast(arg_to_num(arg))))
		print("    - zv (zval *): {}".format(self.get_zval_zv(arg_to_num(arg))))
		print("    - ptr (void *): {}".format(self.get_zval_ptr(arg_to_num(arg))))
		print("    - ce (zend_class_entry *): {}".format(self.get_zval_ce(arg_to_num(arg))))
		print("    - func (zend_function *): {}".format(self.get_zval_func(arg_to_num(arg))))
		print("    - ww (struct)")
		print("      - w1 (uint32_t): {}".format(self.get_zval_ww_w1(arg_to_num(arg))))
		print("      - w2 (uint32_t): {}".format(self.get_zval_ww_w2(arg_to_num(arg))))
		print("   - u1 (union)")
		print("     - v (struct)")
		print("       - type (unsigned char): {}".format(self.get_zval_u1_v_type(arg_to_num(arg))))
		print("       - type_flags (unsigned char): {}".format(self.get_zval_u1_v_type_flags(arg_to_num(arg))))
		print("       - u (union)")
		print("         - extra (uint16_t): {}".format(self.get_zval_u1_v_u_extra(arg_to_num(arg))))
		print("     - type_info (uint32_t): {}".format(self.get_zval_u1_type_info(arg_to_num(arg))))
		print("   - u2 (union)")
		print("     - next (uint32_t): {}".format(self.get_zval_u2_next(arg_to_num(arg))))
		print("     - cache_slot (uint32_t): {}".format(self.get_zval_u2_cache_slot(arg_to_num(arg))))
		print("     - opline_num (uint32_t): {}".format(self.get_zval_u2_opline_num(arg_to_num(arg))))
		print("     - lineno (uint32_t): {}".format(self.get_zval_u2_lineno(arg_to_num(arg))))
		print("     - num_args (uint32_t): {}".format(self.get_zval_u2_num_args(arg_to_num(arg))))
		print("     - fe_pos (uint32_t): {}".format(self.get_zval_u2_fe_pos(arg_to_num(arg))))
		print("     - fe_iter_idx (uint32_t): {}".format(self.get_zval_u2_fe_iter_idx(arg_to_num(arg))))
		print("     - access_flags (uint32_t): {}".format(self.get_zval_u2_access_flags(arg_to_num(arg))))
		print("     - property_guard (uint32_t): {}".format(self.get_zval_u2_property_guard(arg_to_num(arg))))
		print("     - constant_flags (uint32_t): {}".format(self.get_zval_u2_constant_flags(arg_to_num(arg))))
		print("     - extra (uint32_t): {}".format(self.get_zval_u2_extra(arg_to_num(arg))))
		print("- h (zend_ulong): {}".format(self.get_h(arg_to_num(arg))))
		print("- key (zend_string *): {}".format(self.get_key(arg_to_num(arg))))

class PHPString(gdb.Command):
	def __init__(self):
		super(PHPString, self).__init__("php-string", gdb.COMMAND_USER)

	def get_gc_refcount(self, addr):
		refcount = gdb.execute(
			"p/u (*(zend_string *)({})).gc.refcount".format(hex(addr)),
			to_string=True
		)

		return refcount.split(' = ')[1].rstrip("\n")

	def invoke(self, arg, from_tty):
		print("- gc (zend_refcounted_h)")
		print("  - refcount: {}".format(self.get_gc_refcount(arg_to_num(arg))))

# run all registered commands.
PHPArray()
PHPHashTableBucket()
PHPString()
