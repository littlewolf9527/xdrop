import axios from 'axios'

// Create axios instance
const api = axios.create({
    baseURL: '/api/v1',
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json'
    }
})

// Response interceptor - redirect to login on 401
api.interceptors.response.use(
    response => response.data,
    error => {
        if (error.response?.status === 401) {
            window.location.href = '/login'
        }
        return Promise.reject(error)
    }
)

// Rules API
export const rulesApi = {
    // Paginated list (used by Rules page)
    list: (params = {}) => {
        const query = new URLSearchParams()
        if (params.page) query.set('page', params.page)
        if (params.limit) query.set('limit', params.limit)
        if (params.search) query.set('search', params.search)
        if (params.sort) query.set('sort', params.sort)
        if (params.order) query.set('order', params.order)
        if (params.enabled !== undefined) query.set('enabled', params.enabled)
        if (params.action) query.set('action', params.action)
        const qs = query.toString()
        return api.get(`/rules${qs ? '?' + qs : ''}`)
    },
    // Full list (backward-compatible)
    listAll: () => api.get('/rules'),
    // Top-N rules by drop_pps (Dashboard chart)
    top: (limit = 10) => api.get(`/rules/top?limit=${limit}`),
    get: (id) => api.get(`/rules/${id}`),
    create: (data) => api.post('/rules', data),
    update: (id, data) => api.put(`/rules/${id}`, data),
    delete: (id) => api.delete(`/rules/${id}`),
    batchCreate: (rules) => api.post('/rules/batch', { rules }),
    batchDelete: (ids) => api.delete('/rules/batch', { data: { ids } })
}

// Whitelist API
export const whitelistApi = {
    list: () => api.get('/whitelist'),
    create: (data) => api.post('/whitelist', data),
    delete: (id) => api.delete(`/whitelist/${id}`)
}

// Nodes API
export const nodesApi = {
    list: () => api.get('/nodes'),
    get: (id) => api.get(`/nodes/${id}`),
    getStats: (id) => api.get(`/nodes/${id}/stats`),
    register: (data) => api.post('/nodes', data),
    delete: (id) => api.delete(`/nodes/${id}`),
    sync: (id) => api.post(`/nodes/${id}/sync`)
}

// Stats API
export const statsApi = {
    getGlobal: () => api.get('/stats')
}

export default api
