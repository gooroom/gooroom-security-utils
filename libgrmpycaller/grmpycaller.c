/*
* Author: Hyun-min Kim <hmkim@hancom.com>
*/

#include <Python.h>
#include <stdlib.h>

#include "grmpycaller.h"

char*
do_task(const char *task)
{
    PyObject *module_name, *module, *func, *args, *value;
	char *char_value, *return_value = NULL;
	Py_ssize_t value_size = 0;

    putenv(PYTHONPATH);

    Py_Initialize();

    module_name = PyUnicode_FromString(MODULE_NAME);
    module = PyImport_Import(module_name);
    Py_DECREF(module_name);

	if (module == NULL) goto ERR_MODULE;

	func = PyObject_GetAttrString(module, FUNC_NAME);
	if (!func) goto ERR_FUNCTION;

	args = PyTuple_New(1);
	value = PyUnicode_FromString(task);
	PyTuple_SetItem(args, 0, value);

	value = PyObject_CallObject(func, args);
	Py_DECREF(args);
	if (!value) goto ERR_CALL;

	char_value = PyUnicode_AsUTF8AndSize(value, &value_size);
	return_value = (char *)calloc(1, value_size+1);
	memcpy(return_value, char_value, value_size);

	Py_DECREF(value);

ERR_CALL:
	Py_DECREF(func);
ERR_FUNCTION:
    Py_DECREF(module);
ERR_MODULE:
   	Py_Finalize();

	return return_value;
}
