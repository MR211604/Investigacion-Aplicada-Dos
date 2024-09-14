import dbLocal from "db-local";
import crypto from "crypto";
import bcrypt from 'bcrypt'

const { Schema } = new dbLocal({ path: './db' })

const UserSchema = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
})


class AuthRepository {

  static createUser({ username, email, password }) {

    Validations.username(username)
    Validations.email(email)
    Validations.password(password)

    const user = UserSchema.findOne({ username })
    if (user) throw new Error('username already exists')

    const id = crypto.randomUUID()
    const hashedPassword = bcrypt.hashSync(password, 10)

    UserSchema.create({
      _id: id,
      username,
      email,
      password: hashedPassword
    }).save()

    return { _id: id }

  }

  static login({ username, password }) {
    Validations.username(username)
    Validations.password(password)

    const user = UserSchema.findOne({ username })
    if (!user) throw new Error('Usuario o contraseña incorrectos')
    const validPassword = bcrypt.compareSync(password, user.password)
    if (!validPassword) throw new Error('Usuario o contraseña incorrectos')
    
    const { password: _, ...publicUser } = user
 
    return publicUser

  }

}

class Validations {
  static username(username) {
    if (username === undefined) throw new Error('El nombre de usuario es requerido')
    if (typeof username !== 'string') throw new Error('El nombre de usuario debe ser un string')
  }

  static email(email) {
    if (email === undefined) throw new Error('El email es requerido')
    if (typeof email !== 'string') throw new Error('El email debe ser un string')
    if (!email.includes('@')) throw new Error('El email debe ser un email válido')
  }

  static password(password) {
    if (password === undefined) throw new Error('La contraseña es requerida')
    if (typeof password !== 'string') throw new Error('La contraseña debe ser un string')
    if (password.length < 6) throw new Error('La contraseña debe tener al menos 6 caracteres')
  }
}

export { AuthRepository }