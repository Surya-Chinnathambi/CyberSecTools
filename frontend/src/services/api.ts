import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

const api = axios.create({
  baseURL: `${API_URL}/api`,
  headers: {
    'Content-Type': 'application/json'
  }
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authAPI = {
  login: (username: string, password: string) => 
    api.post('/auth/login', { username, password }),
  register: (username: string, email: string, password: string) =>
    api.post('/auth/register', { username, email, password }),
  getMe: () => api.get('/auth/me'),
  getUsage: () => api.get('/auth/usage')
}

export const scanAPI = {
  portScan: (host: string, ports?: number[], scan_type?: string) =>
    api.post('/scan/port', { host, ports, scan_type }),
  webScan: (url: string, options?: any) =>
    api.post('/scan/web', { url, options }),
  getHistory: (limit = 10) =>
    api.get(`/scan/history?limit=${limit}`),
  getResult: (scanId: number) =>
    api.get(`/scan/result/${scanId}`)
}

export const chatAPI = {
  sendMessage: (message: string, context?: string, history?: any[]) =>
    api.post('/chat/message', { message, context, history }),
  analyzeScan: (scan_type: string, results: any) =>
    api.post('/chat/analyze', { scan_type, results })
}

export const dashboardAPI = {
  getStats: () => api.get('/dashboard/stats'),
  getActivity: () => api.get('/dashboard/activity'),
  getVulnDistribution: () => api.get('/dashboard/vulnerability-distribution')
}

export const cveAPI = {
  search: (keyword: string, limit = 20) =>
    api.get(`/cve/search?keyword=${keyword}&limit=${limit}`),
  getDetails: (cveId: string) =>
    api.get(`/cve/details/${cveId}`)
}

export const shodanAPI = {
  search: (query: string, limit = 100) =>
    api.get(`/shodan/search?query=${query}&limit=${limit}`),
  getHost: (ip: string) =>
    api.get(`/shodan/host/${ip}`),
  getAPIInfo: () =>
    api.get('/shodan/api-info')
}

export const exploitsAPI = {
  search: (query: string, exploit_type?: string, platform?: string, limit = 50) =>
    api.get(`/exploits/search?query=${query}&exploit_type=${exploit_type || ''}&platform=${platform || ''}&limit=${limit}`),
  getDetails: (exploitId: string) =>
    api.get(`/exploits/details/${exploitId}`)
}

export const billingAPI = {
  getPlans: () => api.get('/billing/plans'),
  getSubscription: () => api.get('/billing/subscription'),
  createCheckout: (plan: string) =>
    api.post('/billing/create-checkout', { plan })
}

export const reportsAPI = {
  generate: (report_name: string) =>
    api.post('/reports/generate', { report_name }),
  list: () => api.get('/reports/list'),
  download: (reportId: number) =>
    api.get(`/reports/download/${reportId}`, { responseType: 'blob' })
}

export default api
