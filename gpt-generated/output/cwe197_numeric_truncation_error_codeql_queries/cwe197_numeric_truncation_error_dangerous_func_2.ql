/**
 * @name Cwe197 Numeric Truncation Error Dangerous Func 2
 * @description Use of strcpy is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cwe197_numeric_truncation_error_dangerous_func_2
 * @tags security
 *       external/cwe/cwe-197
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "strcpy"
select fc, "Use of strcpy is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf."
