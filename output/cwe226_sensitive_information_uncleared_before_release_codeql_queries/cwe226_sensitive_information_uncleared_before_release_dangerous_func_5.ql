/**
 * @name Cwe226 Sensitive Information Uncleared Before Release Dangerous Func 5
 * @description Use of CWE226_Sensitive_Information_Uncleared_Before_Release__w32_char_alloca_01_good allocates memory on stack without bounds checking. Consider using malloc with proper size validation.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe226_sensitive_information_uncleared_before_release_dangerous_func_5
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "CWE226_Sensitive_Information_Uncleared_Before_Release__w32_char_alloca_01_good"
select fc, "Use of CWE226_Sensitive_Information_Uncleared_Before_Release__w32_char_alloca_01_good allocates memory on stack without bounds checking. Consider using malloc with proper size validation."
