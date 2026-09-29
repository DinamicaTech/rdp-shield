# RDP Shield (Geo + IPBan)

**Estado: desarrollo. No instalar todavía como única protección de un servidor de producción.**

Proyecto para limitar RDP en Windows mediante rangos de país y acceso de emergencia por IP o DNS dinámico. [IPBan](https://github.com/DigitalRuby/IPBan) puede funcionar como capa independiente; su integración automática sigue pendiente.

## Estado

El módulo `src/RDPShield-Resolve-Emergency.ps1` resuelve todas las entradas IPv4 de `EmergencyAccess` y actualiza una regla de firewall **ya creada** con nombre interno `RDPShield-Emergency-TCP`. Si falla la resolución o la validación, mantiene las direcciones actuales.

`src/RDPShield-Update-Country.ps1` descarga los CIDR IPv4 del país configurado desde [IPdeny](https://www.ipdeny.com/ipblocks/data/aggregated/), valida toda la lista y guarda `data/RDPShield-Allow.txt`. Conserva la versión anterior si la descarga o la validación fallan. No modifica el firewall.

`src/RDPShield-Audit-Firewall.ps1` enumera otras reglas Allow activas que pueden cubrir el puerto RDP. `src/RDPShield-Apply-Firewall.ps1` valida la lista y el acceso de emergencia, exporta una copia del firewall y crea o actualiza únicamente cuatro reglas propias: país TCP/UDP y emergencia TCP/UDP. Su modo `-StageOnly` permite prepararlas mientras siguen activas otras reglas; en ese estado el filtro **todavía no limita RDP**.

## Configuración inicial

Copie `config/config.example.json` a `config/config.json` y añada al menos una IP IPv4 o un dominio a `EmergencyAccess`. El archivo local queda excluido de Git para evitar publicar direcciones propias. Ajuste `RdpPort` si RDP usa otro puerto.

```json
"EmergencyAccess": ["mi-acceso.example.org", "203.0.113.10"]
```

Las direcciones del ejemplo son ilustrativas. Compruebe que las suyas resuelven correctamente antes de aplicar cambios.

```powershell
.\src\RDPShield-Resolve-Emergency.ps1 -ResolveOnly
.\src\RDPShield-Update-Country.ps1 -WhatIf
.\src\RDPShield-Update-Country.ps1
.\src\RDPShield-Apply-Firewall.ps1 -ValidateOnly
.\src\RDPShield-Audit-Firewall.ps1
```

La auditoría y la aplicación requieren Windows, PowerShell 5.1 o posterior y permisos de administrador. El proyecto se desarrolla en Windows 10; la instalación completa en Windows Server todavía no está probada. Mantenga una sesión abierta y una vía de acceso alternativa mientras prueba reglas RDP.

Para preparar las reglas en un entorno de prueba elevado:

```powershell
.\src\RDPShield-Apply-Firewall.ps1 -StageOnly -WhatIf
.\src\RDPShield-Apply-Firewall.ps1 -StageOnly
```

El segundo comando cambia el firewall local. Revise la copia `.wfw` que deja en `backup/` y el resultado de la auditoría antes de limitar otras reglas. El proyecto aún no automatiza esa migración ni la reversión; no use estos comandos como instalador de producción.

Una regla Allow limitada por país **no restringe** otras reglas Allow activas para RDP. Antes de afirmar que el filtro geográfico protege el puerto, el instalador deberá detectar y gestionar esas reglas con copia de seguridad y posibilidad de revertir los cambios.

## Próximas piezas

1. Pruebas automatizadas del aplicador y de la auditoría con reglas simuladas.
2. Instalador, tareas programadas, diagnóstico y desinstalación con reversión segura.
3. Pruebas de instalación en Windows Server y publicación de una versión estable.

La carpeta local `Scripts` contiene material de referencia del servidor y está excluida de Git.
