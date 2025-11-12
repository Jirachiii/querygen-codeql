/**
 * @name Cwe253 Incorrect Check Of Function Return Value Dangerous Func 3
 * @description Use of strcat is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cwe253_incorrect_check_of_function_return_value_dangerous_func_3
 * @tags security
 *       external/cwe/cwe-253
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "strcat"
select fc, "Use of strcat is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf."
