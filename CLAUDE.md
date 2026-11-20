# CLAUDE.md — web-enum

Instrucciones permanentes para Claude Code al trabajar en este repositorio.

## Qué es este repo
`web-enum`: herramienta de línea de comandos en Python que, dada una URL
**autorizada**, hace fingerprinting de tecnologías, descubrimiento de contenido
con wordlists, análisis de cabeceras de seguridad y de formularios, y genera
informes priorizados en Markdown y JSON.

Se desarrolla en Windows pero **está pensada para Kali/Parrot**: usa whatweb,
ffuf y feroxbuster si están instalados (con motor nativo en Python como
alternativa) y las wordlists del sistema (SecLists, dirb).

## Ámbito ético (innegociable)
- Solo contra objetivos **autorizados** (labs propios, HTB) o información pública.
- Detección, análisis y documentación. **Nada** de explotación, inyecciones,
  fuerza bruta de credenciales, exfiltración, DoS, persistencia ni evasión de
  defensas (sin rotar User-Agent/IP, sin cabeceras para saltarse WAF).
- El objetivo siempre lo indica el usuario de forma explícita. La herramienta
  exige que esté en `scope` o `--authorized`, y **nunca** sigue enlaces ni
  redirecciones a otros hosts.
- Los formularios se analizan, **nunca se envían**.
- Límites de concurrencia, peticiones/s y presupuesto de peticiones siempre
  activos, también al delegar en ffuf/feroxbuster.
- Las salvaguardas tienen tests. **No las debilites ni las quites**, y añade un
  test por cada salvaguarda nueva.
- Nada de datos reales en el repo: ejemplos y fixtures usan `example.com`,
  `*.htb` ficticios e IPs de documentación (192.0.2.x, 198.51.100.x, 203.0.113.x).
  `reports/` y `*.log` están en `.gitignore`.

## Git (innegociable)
- **Nunca** hagas commit, crees el repo en GitHub, hagas push ni cambies la
  visibilidad sin mi OK expreso. No publiques en PyPI.
- Commits **sin** `Co-Authored-By` ni ninguna mención a Claude o a una IA.
  El autor local de este repo es `SpromBash`.
- Mensajes en imperativo (`Add ffuf backend`, `Fix soft-404 calibration`).
- Antes de cada commit, enséñame `git status` y `git diff`.

## Forma de trabajar
- Primero un plan; cambios pequeños, verificables y reversibles.
- Explícame qué haces y por qué, y qué comandos usas: quiero aprender.
- No afirmes que algo funciona sin comprobarlo. Si algo no se puede comprobar
  aquí (las herramientas de Kali, un objetivo real), dilo claramente.

## Comandos (Windows, desde la raíz)
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\pytest.exe -q
.\.venv\Scripts\pytest.exe --cov=web_enum --cov-branch --cov-report=term-missing
.\.venv\Scripts\mypy.exe
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\python.exe -m build ; .\.venv\Scripts\twine.exe check dist/*
```
Un cambio no está terminado hasta que pasan pytest, mypy y ruff.

## Arquitectura (resumen)
- `cli.py` → `runner.py` (plan → módulos aislados y concurrentes → informe).
- Todo el HTTP pasa por `http.HttpClient` (frontera de origen en cada petición,
  limitador compartido, presupuesto). No crees clientes httpx paralelos.
- Módulos: `analyzers/` (funciones puras sobre respuestas), `discovery/`
  (wordlist, soft-404, seeds, sensibles, motores), `tools/` (procesos externos).
- La lógica de detección es datos: `data/tech_rules.yaml` y
  `data/sensitive_paths.yaml`. Una regla nueva = YAML + un test que la pruebe.
- Severidad: política única en `models.py` (high / medium / low / info).
- Pendiente de verificar en Kali: opciones y formato JSON reales de whatweb,
  ffuf y feroxbuster, y un Ctrl+C real (ver "Verification status" del README).

## Convenciones técnicas
- `mypy --strict` (con `platform = "linux"`), sin `# type: ignore` injustificados.
- **Los tests nunca usan la red ni herramientas externas.** HTTP con `respx`;
  `subprocess` simulado con salidas reales de ffuf/feroxbuster/whatweb como
  fixtures; reloj y `sleep` inyectados.
- Herramientas externas: siempre `argv` en lista, **nunca** `shell=True`; su
  salida (JSON) es no fiable y se valida.
- Los módulos lanzan `ModuleError` para fallos previstos; nunca tumban el escaneo.
  Los errores de usuario son `WebEnumError` con `exit_code`.
- Todo lo que venga del objetivo (HTML, cabeceras, cuerpos) es no fiable: cuerpos
  leídos con límite de tamaño y parsers de la librería estándar.
- Dependencias en tiempo de ejecución: typer, pyyaml, httpx. Pregúntame antes de
  añadir otra.
