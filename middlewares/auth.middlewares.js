const { expressjwt: jwt } = require("express-jwt");

const isAuthenticated = jwt({
  secret: process.env.TOKEN_SECRET,
  algorithms: ["HS256"],
  requestProperty: "payload", // devuelve el payload cuando hayas validado el Token
  getToken: (req) => {
    console.log(req.headers)
    // si el usuario no envia token, lanza un error
    if (req.headers === undefined || req.headers.authorization === undefined) {
      console.log("No hay Token")
      return null;
    }

    // si el token existe, extraelo del string y retornalo de la funcion
    const tokenArr = req.headers.authorization.split(" ")
    const tokenType = tokenArr[0]
    const token = tokenArr[1]

    if (tokenType !== "Bearer") {
      console.log("Tipo de token incorrecto")
      return null;
    }

    // a partir de este punto el token ha sido recibido
    // para validarlo lo retornamos de la funcion
    console.log("el token ha sido entregado")
    return token

  }
})


module.exports = isAuthenticated