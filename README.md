# AutoRDPwn: The Shadow Attack Framework

![AutoRDPwn](https://user-images.githubusercontent.com/34335312/45108867-329c6880-b13e-11e8-9627-abd28d583772.png)

AutoRDPwn es un script creado en Powershell y diseñado para automatizar el ataque Shadow en equipos Microsoft Windows. Esta vulnerabilidad permite a un atacante remoto visualizar el escritorio de su víctima sin su consentimiento, e incluso controlarlo a petición. Para su correcto funcionamiento, es necesario cumplir los requisitos que se describen en la guía de uso.

# Cambios

## Versión 2.8
• Eliminada la opción de elegir la arquitectura del sistema remoto

## Versión 2.6
• Correción de errores

• Auto-detección de Id de sesión

*El resto de cambios se pueden consultar en el fichero CHANGELOG


# Uso
Ejecución en una línea:

powershell -ExecutionPolicy Bypass "iwr https://goo.gl/HSkAXP -Outfile %TEMP%\AutoRDPwn.ps1 ; %TEMP%\AutoRDPwn.ps1"

La guía detallada de uso se encuentra en los siguientes enlaces: 

https://darkbyte.net/autordpwn-the-shadow-attack-framework 

https://darkbyte.net/cambios-y-mejoras-en-autordpwn

# Licencia
Este proyecto está licenciando bajo la licencia GNU 3.0 - ver el fichero LICENSE para más detalles.


# Créditos y Agradecimientos
• Mark Russinovich por su herramienta PsExec -> https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

• Marc R Kellerman por su herramienta Invoke-CommandAs -> https://github.com/mkellerman/Invoke-CommandAs

• Stas'M Corp. por su herramienta RDP Wrapper -> https://github.com/stascorp/rdpwrap

# Contacto
Este software no ofrece ningún tipo de garantía. Su uso es exclusivo para entornos educativos y/o auditorías de seguridad con el correspondiente consentimiento del cliente. No me hago responsable de su mal uso ni de los posibles daños causados por el mismo.

Para más información, puede contactar a través de info@darkbyte.net
