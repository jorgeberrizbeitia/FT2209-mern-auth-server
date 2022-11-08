const router = require("express").Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User.model");
const jwt = require("jsonwebtoken");
const isAuthenticated = require("../middlewares/auth.middlewares");

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
router.post("/login", async (req, res, next) => {

  console.log(req.body)
  const { email, password } = req.body

  // 1. Validaciones de backend

  // que todos los campos esten llenos
  if (email === "" || password === "") {
    res.status(400).json({ errorMessage: "Debe tener email y contraseña" })
    return; // detiene la ejecución de la ruta
  }

  try {
    
    // que el usuario exista
    const foundUser = await User.findOne({email: email})
    console.log(foundUser)
    if (foundUser === null) {
      res.status(400).json({errorMessage: "Credenciales no validas"})
      return;
    }

    // que la contraseña sea correcta
    const isPasswordValid = await bcrypt.compare(password, foundUser.password)
    if (isPasswordValid === false) {
      res.status(400).json({errorMessage: "Credenciales no validas"}) // buena practica (privacidad de usuarios) misma respuesta que anterior clausula de guardia
      return;
    }

    // a partir de este punto, el usuario ha sido validado...

    // 2. crear algo parecido a la sesión (TOKEN) y enviarlo al cliente
    
    // payload es la informacion del usuario dueño del Token
    const payload = {
      _id: foundUser._id,
      email: foundUser.email
      // ! si tuviesemos username, o role u otra info importante del usuario, tiene que ir aqui.
    }

    // a .sign se le pasan 3 argumentos
    const authToken = jwt.sign(
      payload, // la info del usuario, que será accesible en diferentes partes de server/client
      process.env.TOKEN_SECRET, // palabra SUPER secreta que double encrypta el token.
      { algorithm: "HS256", expiresIn: "6h" } // configuraciones adicionales del Token (Header)
    )

  
    // enviar el Token al cliente
    res.status(200).json({ authToken: authToken })
  
  
  } catch (error) {
    next(error)
  }


})


// GET "/api/auth/verify" => para que el BE le diga al FE si el usuario ya ha sido validado
router.get("/verify", isAuthenticated, (req, res, next) => {

  // esta ruta va a verificar que el usuario tiene un Token valido
  // normalmente se utilizará para la primera vez que el usuario visita la web

  // como tenemos acceso a informacion del usuario haciendo esta llamada???
  console.log(req.payload)
  // para acceder a req.payload, DEBEMOS tener isAuthenticated en la Ruta.

  res.status(200).json({ user: req.payload })

})


module.exports = router;