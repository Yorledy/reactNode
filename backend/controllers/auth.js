const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db'); // Asegúrate de que esta ruta sea correcta

// Función para registrar un usuario
const registrarUsuario = (req, res) => {
    const { nombre, apellido, email, password } = req.body;
    
    // Verificar que todos los campos estén presentes
    if (!nombre || !apellido || !email || !password) {
        return res.status(400).json({ message: 'Todos los campos son requeridos' });
    }

    // Verificar si el usuario ya existe
    db.query('SELECT * FROM usuarios WHERE email = ?', [email], (error, results) => {
        if (error) return res.status(500).json({ message: 'Error en la base de datos' });
        if (results.length > 0) return res.status(400).json({ message: 'El usuario ya existe' });

        // Hash de la contraseña
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).json({ message: 'Error al encriptar la contraseña' });

            // Insertar nuevo usuario en la base de datos
            db.query('INSERT INTO usuarios (nombre, apellido, email, password) VALUES (?, ?, ?, ?)', 
                [nombre, apellido, email, hash], (error, results) => {
                if (error) return res.status(500).json({ message: 'Error en la base de datos' });
                res.status(201).json({ message: 'Usuario registrado con éxito' });
            });
        });
    });
};

// Función para iniciar sesión
const iniciarSesion = (req, res) => {
    const { email, password } = req.body;
    
    // Verificar que los campos estén presentes
    if (!email || !password) {
        return res.status(400).json({ message: 'Todos los campos son requeridos' });
    }

    // Buscar el usuario en la base de datos
    db.query('SELECT * FROM usuarios WHERE email = ?', [email], (error, results) => {
        if (error) return res.status(500).json({ message: 'Error en la base de datos' });
        if (results.length === 0) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });

        const usuario = results[0];

        // Comparar la contraseña
        bcrypt.compare(password, usuario.password, (err, result) => {
            if (err) return res.status(500).json({ message: 'Error al comparar contraseñas' });
            if (!result) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });

            // Generar token JWT
            const token = jwt.sign(
                { id: usuario.id, email: usuario.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.status(200).json({ token });
        });
    });
};

module.exports = { registrarUsuario, iniciarSesion };

