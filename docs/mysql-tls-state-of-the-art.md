# Investigación — TLS de MySQL en un proxy que inspecciona queries

> Estado: **investigación (reafirma el enfoque, corrige un detalle)**
> Creado: 2026-07-07
> Motivo: antes de implementar la máquina de estados de auth, validar el enfoque
> contra la documentación del protocolo y el estado del arte (ProxySQL/MaxScale).

## Pregunta

El intento de "upstream TLS por reescritura de handshake" falla con
`Got an error reading communication packets` **después** de que el server parsea
el usuario. ¿El enfoque es correcto y falta un detalle, o hay que rediseñar?

## Evidencia del protocolo (MariaDB/MySQL Client-Server Protocol)

Secuencia canónica de conexión con TLS (fuente: MariaDB KB, "Connecting"):

1. Server → cliente: **Initial Handshake** (contiene capabilities + nonce/scramble).
2. Si TLS: cliente → server **SSLRequest packet** y *switches to SSL mode* para
   los mensajes siguientes.
3. Cliente → server: **Handshake Response** (sobre TLS).
4. Server → cliente: **una de**:
   - **OK_Packet** (éxito), o
   - **ERR_Packet** (error), o
   - **"Further authentication data, if requested by the authentication plugin"**
     — y textualmente: *"Client may have many exchanges with the server"*, que
     *"ends with server sending either OK_Packet or ERR_Packet"*.

**Conclusión del protocolo:** el handshake NO termina en el Handshake Response.
Hay un sub-protocolo de autenticación (auth-switch / auth-more-data) con **N
intercambios** cliente↔server que solo termina con OK/ERR. `caching_sha2_password`
(default en MySQL 8) y el auth-switch usan exactamente esto.

## Por qué falló nuestro intento

El intento arrancaba, tras reenviar el Handshake Response, el **relay
bidireccional + el loop de intercepción de comandos en paralelo**. Pero el server
todavía estaba en la fase de auth (esperando más paquetes de auth del cliente en
orden estricto). El relay concurrente y el "command-phase gate" (seq==0) no median
ese intercambio secuencial → el server recibe algo fuera de orden y aborta con
"error reading communication packets" (tras haber parseado el usuario, que es
justo lo que observamos).

El diagnóstico se confirmó empíricamente: `Ssl_accepts` del server sube (el TLS
backend SÍ se establece) y el log dice `Aborted connection … user: 'app' … (Got
an error reading communication packets)` — el fallo es en la **continuación de
auth**, no en el TLS ni en el Handshake Response.

## Estado del arte (ProxySQL / MaxScale)

- **MaxScale** (proxy MySQL de MariaDB) trata frontend (cliente→proxy) y backend
  (proxy→server) como **conexiones independientes**: *"listeners, servers … must
  be configured to use SSL"*. Cada hop tiene su propia terminación TLS y su propio
  handshake; el proxy **completa la fase de conexión de cada lado por separado**,
  no reenvía paquetes de auth de un lado al otro.
- **ProxySQL** hace lo mismo: mantiene un pool de conexiones backend que **el
  propio proxy autentica** contra el server (con las credenciales que conoce), y
  autentica a los clientes en el frontend por separado. El proxy es un
  *participante* del handshake en ambos lados, no un relay de bytes de auth.

## Reafirmación / corrección del enfoque

**Reafirmado:** interponerse en el handshake (un solo nonce, SSLRequest, TLS) es
la dirección correcta — coincide con el protocolo y con ProxySQL/MaxScale.

**Corregido (el error de nuestro intento):** NO se puede reenviar el Handshake
Response y saltar al relay/command-loop. El proxy debe **conducir la fase de
conexión completa como una máquina de estados secuencial**, paquete por paquete,
SIN relay concurrente, hasta que el server emita OK_Packet (o ERR_Packet). Recién
entonces arranca el relay + la intercepción de comandos.

### Diseño resultante (máquina de estados de auth)

Para el hop **upstream TLS** (proxy→MySQL), tras el TLS handshake:

```
loop:
  reenviar client→server el siguiente paquete de auth del cliente
  leer server→client la respuesta:
    OK_Packet  → auth completa: salir del loop, iniciar relay + intercept
    ERR_Packet → propagar el error al cliente y cerrar
    otro       → (auth-switch / more-data) reenviar al cliente y continuar el loop
```

Es un **bucle ping-pong estricto y secuencial** durante la fase de conexión (sin
las dos tareas concurrentes), que respeta el "many exchanges" del protocolo. Una
vez visto el OK, la sesión pasa a la fase de comandos, donde sí aplica el modelo
relay + intercept que ya funciona.

Nota: reconocer OK (0x00) vs ERR (0xFF) vs auth-more (0x01/0xFE) en el **primer
byte del payload** del paquete server→client es suficiente para el control de
flujo del loop; no hay que entender el contenido de la auth (el proxy no
reimplementa caching_sha2 — solo transporta los paquetes en orden y detecta el
fin). Esto mantiene el passthrough de credenciales sin reimplementar plugins.

## Alcance confirmado

- **Upstream TLS** (proxy→MySQL): máquina de estados de auth como arriba.
- **Client TLS** (cliente→proxy): simétrico — el proxy termina TLS del lado del
  cliente (ya existe `client_tls` / acceptor), y en el frontend conduce la fase
  de conexión hasta emitir OK al cliente.
- No se reimplementa ningún plugin de auth: el proxy media (transporta en orden)
  los paquetes; el cálculo del scramble sigue siendo entre cliente y server real.
