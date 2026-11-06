# Squadwatch

Auditor de seguridad para los agentes de IA de tu equipo. Te dice qué agentes
hay instalados, qué pueden hacer, qué exponen y qué riesgo tienen, y te
explica cómo corregir cada problema.

```
$ squadwatch scan
Squadwatch 0.1.0 · escaneo estático (no se ha ejecutado código de terceros)
✓ 3 agentes · 6 servidores MCP · 412 ficheros leídos · 90 ms

 AGENTE       ESTADO               RIESGO              MCP  HALLAZGOS
 Claude Code  ■ activo · pid 4242  84      ████████░░  5    1 crítico · 3 altos · 1 medio
 Codex CLI    ■ activo · pid 4310  36      ████░░░░░░  1    1 alto
 Cursor       instalado            18      ██░░░░░░░░  –    sin hallazgos

 Riesgo del equipo 69/100 (alto) · 1 crítico · 4 altos · 1 medio
```

## Principios

- **Solo lectura.** Lee ficheros de configuración, `/proc` y los puertos en
  escucha. Nunca arranca un agente ni un servidor MCP.
- **Local.** No hace ninguna conexión de red. El dashboard solo escucha en
  `127.0.0.1` y no carga nada de internet.
- **Sin secretos en claro.** Las credenciales se muestran enmascaradas
  (`••••a1B2`) en la terminal, en JSON, en el historial y en el dashboard.
- **Cada hallazgo con evidencia.** Fichero y línea, por qué importa y qué hacer.

## Instalación

Necesitas Go 1.22 o posterior.

```sh
go install github.com/sergio-lopez-dev/squadwatch/cmd/squadwatch@latest
```

O desde el código:

```sh
git clone https://github.com/sergio-lopez-dev/squadwatch
cd squadwatch
make install      # compila y copia el binario a ~/.local/bin
```

## Uso

| Comando | Qué hace |
|---|---|
| `squadwatch scan` | Inventario y riesgos. Guarda el escaneo en el historial. |
| `squadwatch scan --format md -o informe.md` | Informe en Markdown para compartir. |
| `squadwatch scan --format json` | Todo el escaneo en JSON. |
| `squadwatch agents` | Lista de agentes detectados. |
| `squadwatch show claude-code` | Detalle de un agente: permisos, MCP, hooks, instrucciones, trifecta. |
| `squadwatch mcp` | Servidores MCP de todos los agentes. |
| `squadwatch findings` | Hallazgos con evidencia. Filtros: `-min high`, `-agent codex`, `MCP-001`. |
| `squadwatch trifecta` | Qué agentes juntan datos privados, contenido no fiable y salida. |
| `squadwatch paths` | Caminos de ataque. |
| `squadwatch diff` | Qué ha cambiado desde el último escaneo guardado. |
| `squadwatch history` | Evolución del riesgo. |
| `squadwatch serve` | Dashboard en http://127.0.0.1:7777. |
| `squadwatch rules` | Reglas que comprueba. |

Casi todos los comandos aceptan `-json`. `scan` y `findings` aceptan
`--fail-on high` para usarlos en CI: salen con código 1 si hay hallazgos de esa
severidad o peor.

## Qué detecta

**Agentes:** Claude Code, Cursor, Codex CLI, Gemini CLI, VS Code + Copilot,
Windsurf, Claude Desktop, Aider, Ollama y LM Studio.

**Reglas:**

| ID | Severidad | Qué comprueba |
|---|---|---|
| TRI-001 | Crítica | El agente junta datos privados, contenido no fiable y una salida sin confirmación |
| AGT-001 | Crítica | Modos sin confirmación (bypassPermissions, yolo, auto-run, approval never + sin sandbox) |
| AGT-002 | Alta | Shell, red o intérpretes con comodín permitidos sin preguntar (`Bash(curl *)`, `Bash(node -e *)`) |
| AGT-003 | Media | Codex sin aprobaciones dentro de la sandbox |
| AGT-004 | Alta | Codex sin sandbox |
| SEC-001 | Alta | Lectura sin preguntar de todo el HOME o del disco |
| MCP-001 | Alta | Credenciales en texto plano en la configuración MCP |
| MCP-002 | Media | Servidores MCP sin versión fijada (`npx paquete`, `@latest`, imágenes sin digest) |
| MCP-003 | Alta | Servidores MCP remotos por `http://` |
| MCP-006 | Alta | Servidor de ficheros con raíz en `/` o en el HOME |
| MCP-007 | Media | Aprobación automática de los `.mcp.json` de cualquier proyecto |
| HK-001 | Alta | Hooks que ejecutan scripts que otros usuarios pueden modificar |
| INS-001 | Alta | Ficheros de instrucciones con texto invisible (caracteres de etiqueta Unicode, bidi, ancho cero), que además se decodifica |
| NET-001 | Alta | Servidores de modelos (Ollama, LM Studio) accesibles desde la red |

### La trifecta letal

Un agente es crítico cuando junta tres cosas: acceso a datos privados,
contacto con contenido no fiable y una forma de enviar datos fuera **sin
pedir confirmación**. Squadwatch calcula cada lado sumando lo que el agente
hace por sí mismo y lo que le añaden sus servidores MCP. Una salida que pide
confirmación cuenta como parcial, no como completa.

Una regla de permisos con un comando exacto, como
`Bash(curl -s https://example.com/)`, no cuenta como salida: solo permite ese
comando literal. Sí cuentan las reglas con comodín, como `Bash(curl *)`, o las
que dejan elegir el código que se ejecuta, como `Bash(node -e *)` o
`Bash(bundle exec *)`.

**Por proyecto.** En Claude Code, los permisos y servidores MCP de un proyecto
solo valen dentro de ese proyecto. Squadwatch calcula la trifecta de cada
proyecto por separado y te dice en cuál se cumple, en lugar de mezclar reglas
de proyectos distintos.

**Mitigaciones.** Antes de dar una salida por abierta, Squadwatch busca qué la
frena:

- **Hooks `PreToolUse` sobre Bash** que revisan comandos de red (curl, wget…)
  y pueden bloquearlos. Lee el script del hook para comprobarlo.
- **La sandbox de Bash** de Claude Code activada.
- **Reglas `deny` sobre `~/.ssh`**, que rebajan `SEC-001` de alto a medio.

Una salida mitigada pasa a contar como "con confirmación" y aparece marcada
como mitigada. Si tienes hooks pero ninguno revisa la red, también te lo dice.

### Puntuación

- **Puntos de un agente:** 30 por hallazgo crítico, 15 por alto, 6 por medio y
  2 por bajo, más 2 por cada evidencia adicional (hasta 3). Se suman 5 por
  cada lado de la trifecta que tiene sin confirmación y 2 si lo tiene con
  confirmación.
- **Riesgo de un agente (0–100):** `100 × (1 − e^(−puntos/60))`. La curva no
  llega a 100, así que arreglar cualquier problema siempre baja el número. Un
  agente con un hallazgo crítico nunca baja de 70.
- **Riesgo del equipo:** 60 % el agente más arriesgado más 40 % la media de
  los demás.

## Historial

Cada `squadwatch scan` (y cada «Escanear de nuevo» del dashboard) se guarda
en `~/.local/share/squadwatch/scans/` con permisos `0600`. Se conservan los
100 últimos. `squadwatch scan --no-save` no guarda nada.

## Desarrollo

```sh
make test         # tests, incluido uno que comprueba que ningún secreto sale en la salida
make vet
```

Estructura:

```
cmd/squadwatch/       CLI
internal/detect/      un detector por agente; solo leen ficheros, /proc y sockets
internal/mcpcat/      catálogo de capacidades de servidores MCP
internal/rules/       reglas y textos de los hallazgos
internal/risk/        trifecta, caminos de ataque y puntuación
internal/redact/      enmascarado de secretos
internal/store/       historial de escaneos
internal/diff/        comparación entre escaneos
internal/report/      salida de terminal y Markdown
internal/server/      dashboard local (HTML embebido en el binario)
```

## Limitaciones conocidas

- Linux es la plataforma principal. En macOS funcionan los detectores, pero
  aún no se leen los puertos en escucha.
- Cursor guarda parte de sus ajustes en una base de datos interna que todavía
  no se lee.
- Las capacidades de un servidor MCP se deducen de su nombre y su paquete. Los
  servidores que no están en el catálogo aparecen como «desconocidas».
- No se sondean los servidores MCP en vivo, así que todavía no se detectan
  cambios en las descripciones de sus herramientas (*rug pulls*).

## Próximos pasos

`squadwatch watch` (vigilancia continua), `squadwatch policy apply` (una
política para todos los agentes), sondeo de servidores MCP en sandbox,
honeytokens y lectura de las sesiones de los agentes.
