/**
 * @name Cwe242 Use Of Inherently Dangerous Function Dangerous Func 2
 * @description Use of gets is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cwe242_use_of_inherently_dangerous_function_dangerous_func_2
 * @tags security
 *       external/cwe/cwe-242
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "gets"
select fc, "Use of gets is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf."
