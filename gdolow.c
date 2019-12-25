/* Valid for Python 2.4 ... 2.7 on 32-bit systems. GIL must be held */

struct object;
struct typeobject;

struct buffer_procs {
  int (*bf_getreadbuffer) (struct object *, int, void **);
  int (*bf_getwritebuffer)(struct object *, int, void **);
  int (*bf_getsegcount)   (struct object *, int *);
  int (*bf_getcharbuffer) (struct object *, int, const char **);
};

struct object {
  int ob_refcnt;  /* struct object *ob_next; */
  struct typeobject *ob_type;  /* struct object *ob_prev; */
  /* ... */ int ob_others;
};

struct typeobject {
  int ob_refcnt;  /* struct object *ob_next; */
  struct typeobject *ob_type;  /* struct object *ob_prev; */
  int ob_size;
  const char *tp_name;
  int tp_basicsize;
  int tp_itemsize;
  void *tp_dealloc;
  void *tp_print;
  void *tp_setattr;
  void *tp_getattr;
  void *tp_compare;
  void *tp_repr;
  void *tp_as_number;
  void *tp_as_sequence;
  void *tp_as_mapping;
  void *tp_hash;
  void *tp_call;
  void *tp_str;
  void *tp_getattro;
  void *tp_setattro;
  struct buffer_procs *tp_as_buffer;
  int tp_flags;
  const char *tp_doc;
  /* ... */
};

/* Based on PyObject_AsCharBuffer. */
const char *gdolow(struct object *obj) {
  struct typeobject *tobj;
  struct buffer_procs *pb;
  const char *pp;

  tobj = obj->ob_type->ob_type;
  /* If Py_TRACE_REFS, skip ob_next and ob_prev. */
  if (tobj->ob_type != tobj) {
    obj = (struct object*)&obj->ob_others;
    pb = ((struct typeobject*)&obj->ob_type->ob_size)->tp_as_buffer;
  } else {
    pb = obj->ob_type->tp_as_buffer;
  }
  if (!pb || !pb->bf_getcharbuffer || !pb->bf_getsegcount) return 0;
  if ((*pb->bf_getsegcount)(obj, 0) != 1) return 0;
  if ((*pb->bf_getcharbuffer)(obj, 0, &pp) < 0) return 0;
  return pp;
}

#if 0  /* Python 3 */
int
PyObject_AsCharBuffer(PyObject *obj,
                      const char **buffer,
                      Py_ssize_t *buffer_len)
{
    PyBufferProcs *pb;
    Py_buffer view;

    if (obj == NULL || buffer == NULL || buffer_len == NULL) {
        null_error();
        return -1;
    }
    pb = obj->ob_type->tp_as_buffer;
    if (pb == NULL || pb->bf_getbuffer == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "expected an object with the buffer interface");
        return -1;
    }
    if ((*pb->bf_getbuffer)(obj, &view, PyBUF_SIMPLE)) return -1;

    *buffer = view.buf;
    *buffer_len = view.len;
    if (pb->bf_releasebuffer != NULL)
        (*pb->bf_releasebuffer)(obj, &view);
    Py_XDECREF(view.obj);
    return 0;
}
#endif
