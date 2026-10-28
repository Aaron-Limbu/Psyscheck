# Just powershell system check 

requires adminstrative privelege to run

command 
```powershell
.\scan.ps1 -Status All -UserName "test" -Export test
```
also before that 
```powershell
Set-ExcutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```