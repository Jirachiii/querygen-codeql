/**
 * @name Cwe253 Incorrect Check Of Function Return Value Dangerous Func 1
 * @description Use of strcpy is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cwe253_incorrect_check_of_function_return_value_dangerous_func_1
 * @tags security
 *       external/cwe/cwe-253
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "strcpy"
select fc, "Use of strcpy is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf."
