import axios from 'axios'

const authClient = axios.create({
    baseURL: '/api/auth',
    timeout: 10000,
    headers: { 'Content-Type': 'application/json' }
})

export const authApi = {
    login: (username, password) => authClient.post('/login', { username, password }).then(r => r.data),
    logout: () => authClient.post('/logout').then(r => r.data),
    check: () => authClient.get('/check').then(r => r.data)
}
