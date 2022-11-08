const router = require("express").Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User.model");

// aqui iran nuestras rutas de Autenticación

// POST "/api/auth/signup" => registrar a un usuario (recibiendo email y contraseña)
router.post("/signup", async (req, res, next) => {

  console.log(req.body)
  const { email, password } = req.body

  // 1. Hacer validaciones de Backend
  // if (!email || !password) {
  if (email === "" || password === "") {
    res.status(400).json({ errorMessage: "Debe tener email y contraseña" })
    return; // detiene la ejecución de la ruta
  }

  // !NO OLVIDAR IMPLEMENTARLO SIGUIENDO COMO HICIMOS EN M2
  // la constraseña sea suficientemente fuerte
  // el email tenga la estructura correcta
  // el usuario no esté duplicado

  
  try {
    
    // 2. codificar la contraseña
    const salt = await bcrypt.genSalt(10)
    const hashPassword = await bcrypt.hash(password, salt)

    const newUser = {
      email: email,
      password: hashPassword
    }

    // 3. crear el usuario
    await User.create(newUser)
    // ... si llega a este punto ya ha creado el usuario

    // 4. enviar un mensaje de OK al FE

    res.status(201).json("Usuario registrado correctamente")

  } catch (error) {
   next(error) 
  }
})

// POST "/api/auth/login" => validar credenciales del usuario


// GET "/api/auth/verify" => para que el BE le diga al FE si el usuario ya ha sido validado



module.exports = router;