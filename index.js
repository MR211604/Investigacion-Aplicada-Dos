import express from 'express';
import { AuthRepository } from './auth-repository.js';
import { JWT_KEY, PORT } from './constants.js';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const app = express()
app.use(express.json())
app.use(cookieParser())

app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body
  try {
    const response = AuthRepository.createUser({ username, password, email })
    return res
      .status(201).json({
        ok: true,
        message: 'Usuario creado exitosamente',
        response
      })
  } catch (error) {
    return res.status(400).send(error.message)
  }
})

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const response = AuthRepository.login({ username, password })
    const token = jwt.sign({ _id: response._id, username: response.username }, JWT_KEY, { expiresIn: '24h' })
    return res
      .cookie('token', token, {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 //Duracion de una hora
      })
      .status(200).json({
        ok: true,
        message: 'Usuario autenticado exitosamente',
        response,
        token
      })
  } catch (error) {
    return res.status(404).send(error.message)
  }
})

app.get('/api/protected-resource', (req, res) => {
  //El token, nos llegara como Bearer <token>, asi que lo separamos:
  const token = req.header('Authorization').replace(/\s+/g, ' ').trim().split(' ')[1]
  if (token !== req.cookies.token) return res.status(401).send('No autorizado')
  try {
    const payload = jwt.verify(token, JWT_KEY)
    return res.status(200).json({
      ok: true,
      message: 'Recurso protegido',
      payload
    })
  } catch (error) {
    return res.status(401).json({
      ok: false,
      message: 'Token inválido',
      error: error.message
    })
  }
})

app.post('/api/logout', (req, res) => {
  const token = req.header('Authorization').replace(/\s+/g, ' ').trim().split(' ')[1]
  if (token === req.cookies.token) {
    return res.clearCookie('token').status(200).send('Sesión cerrada exitosamente')
  } else {
    return res.status(401).send('Token inválido')
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})