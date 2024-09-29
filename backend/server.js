const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config(); // Para cargar variables de entorno desde el archivo .env

console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('PORT:', process.env.PORT);



const app = express();
const PORT = process.env.PORT || 5001;

// Middleware para analizar solicitudes JSON
app.use(bodyParser.json());
app.use(cors());

// Conexión a la base de datos MySQL
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306
});

// Conectar a la base de datos
db.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        return;
    }
    console.log('Conexión exitosa a la base de datos MySQL');
});

// Ruta de registro de usuario
app.post('/register', async (req, res) => {
    console.log('Cuerpo de la solicitud:', req.body); // Imprime el cuerpo de la solicitud
    try {
        const { nombre, apellido, email, password } = req.body;

        // Verificar si el usuario ya existe
        db.query('SELECT * FROM usuario WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error('Error en la consulta SELECT:', err); // Imprime el error
                return res.status(500).send('Error en el servidor: SELECT query failed');
            }

            if (results.length > 0) {
                return res.status(400).send('El usuario ya está registrado');
            }

            // Encriptar la contraseña
            const hashedPassword = await bcrypt.hash(password, 10);

            // Guardar usuario en la base de datos
            db.query('INSERT INTO usuario (nombre, apellido, email, password) VALUES (?, ?, ?, ?)',
                [nombre, apellido, email, hashedPassword], (err, results) => {
                    if (err) {
                        console.error('Error al registrar el usuario:', err); // Log detallado
                        return res.status(500).send('Error al registrar el usuario');
                    }
                    res.status(201).send('Usuario registrado exitosamente');
                });
        });
    } catch (error) {
        console.error('Error inesperado en la ruta de registro:', error); // Imprime cualquier error inesperado
        res.status(500).send('Error en el servidor: Error inesperado');
    }
});

// Inicio de sesión de usuario
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    console.log('Email ingresado:', email); // Log del email recibido

    // Verificar si el usuario existe
    db.query('SELECT * FROM usuario WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Error en la consulta SELECT:', err);
            return res.status(500).send('Error en el servidor');
        }

        console.log('Resultados de la consulta:', results); // Log de resultados de la consulta

        if (results.length === 0) {
            return res.status(400).send('Usuario no encontrado');
        }

        // Comparar la contraseña ingresada con la almacenada
        const validPassword = await bcrypt.compare(password, results[0].password);
        if (!validPassword) {
            return res.status(401).send('Contraseña incorrecta');
        }

        // Generar token JWT
        const token = jwt.sign({ id: results[0].id, email: results[0].email }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });

        res.status(200).json({ token });
    });
});


// Levantar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});


