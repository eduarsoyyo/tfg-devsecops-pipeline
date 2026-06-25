# Correcciones de Seguridad - TFG Eduardo Ybarra Puig

Documentación de 3 correcciones sobre vulnerabilidades detectadas en el análisis SAST/DAST de DVWA.

## Corrección 1 — SQL Injection

**Antes (vulnerable):** concatenación directa de la entrada del usuario en la consulta.
```php
$query = "SELECT * FROM users WHERE id = '$id'";
$result = mysqli_query($conn, $query);
```

**Después (seguro):** consulta parametrizada (prepared statement).
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
```

**Por qué cierra el fallo:** la consulta parametrizada separa el código SQL de los datos, de modo que la entrada del usuario nunca se interpreta como instrucción SQL. Mitiga la SQLi explotada en DVWA (CVSS 9.8).

## Corrección 2 — Cross-Site Scripting (XSS)

**Antes (vulnerable):** salida sin escapar.
```php
echo "Bienvenido " . $_GET['name'];
```

**Después (seguro):** escapado de salida.
```php
echo "Bienvenido " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

**Por qué cierra el fallo:** htmlspecialchars convierte caracteres como < y > en entidades HTML inofensivas, evitando que el navegador ejecute el script inyectado (CVSS 6.1).

## Corrección 3 — Validación de entrada

**Antes (vulnerable):** se usa la entrada sin validar.
```php
$id = $_GET['id'];
```

**Después (seguro):** validación de tipo y rango.
```php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false) {
    die('Entrada no valida');
}
```

**Por qué cierra el fallo:** se valida que la entrada sea exactamente lo esperado (un entero) antes de usarla, rechazando datos maliciosos.
