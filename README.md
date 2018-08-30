# AutoRDPwn: The Shadow Attack Framework

![autordpwn](https://user-images.githubusercontent.com/34335312/44861779-8bb95780-ac79-11e8-97e8-3008df1f0d5b.png)

AutoRDPwn es un script creado en PowerShell para automatizar el proceso de visualización y control del escritorio de forma remota y sin consentimiento del usuario en equipos Windows. Para su correcto funcionamiento es necesario cumplir algunos requisitos que se describen en la guía de uso.


# Cambios

## Versión 2.6
• Correción de errores

• Auto-detección de Id de sesión

## Versión 2.4
• Nuevo tipo de ataque disponible: ScheduleTask

## Versión 2.2
• Mejoras y cambios de código

• Añadida la opción de visualizar o controlar el equipo remoto

• Eliminado el popup de PsExec con el argumento -accepteula

## Versión 2.0
• Primera release pública


# Uso
Ejecución en una línea:

powershell -ExecutionPolicy Bypass "iwr https://goo.gl/HSkAXP -Outfile "%TEMP%\AutoRDPwn.ps1" ; %TEMP%\AutoRDPwn.ps1"

La guía detallada de uso se encuentra en: https://darkbyte.net/autordpwn-the-shadow-attack-framework


# Licencia
Este proyecto está licenciando bajo la licencia GNU 3.0 - ver el fichero LICENSE para más detalles.


# Créditos y Agradecimientos
• Mark Russinovich por su herramienta PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• Marc R Kellerman por su herramienta Invoke-CommandAs -> https://github.com/mkellerman/Invoke-CommandAs

• Stas'M Corp. por su herramienta RDP Wrapper -> https://github.com/stascorp/rdpwrap

# Contacto
Este software no ofrece ningún tipo de garantía. Su uso es exclusivo para entornos educativos y/o auditorías de seguridad con el correspondiente consentimiento del cliente. No me hago responsable de su mal uso ni de los posibles daños causados por el mismo.

Para más información, puede contactar a través de info@darkbyte.net
