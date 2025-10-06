import { useState } from 'react'
import { motion } from 'framer-motion'
import { authAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { scaleIn, fadeIn, pageTransition } from '@/utils/animations'

interface LoginProps {
  onLogin: () => void
}

export default function Login({ onLogin }: LoginProps) {
  const [isLogin, setIsLogin] = useState(true)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      if (isLogin) {
        const response = await authAPI.login(username, password)
        localStorage.setItem('token', response.data.access_token)
        showToast.success('Login successful!')
        onLogin()
      } else {
        const response = await authAPI.register(username, email, password)
        localStorage.setItem('token', response.data.access_token)
        showToast.success('Registration successful!')
        onLogin()
      }
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Authentication failed')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <motion.div 
      className="min-h-screen bg-gray-950 flex items-center justify-center px-4"
      variants={pageTransition}
      initial="hidden"
      animate="visible"
      exit="exit"
    >
      <motion.div
        variants={scaleIn}
        initial="hidden"
        animate="visible"
        className="w-full max-w-md"
      >
        <div className="relative">
          <motion.div
            className="absolute -inset-1 bg-gradient-to-r from-cyan-600 via-purple-600 to-pink-600 rounded-2xl blur-lg opacity-75"
            animate={{
              scale: [1, 1.05, 1],
              rotate: [0, 360]
            }}
            transition={{
              scale: { duration: 2, repeat: Infinity },
              rotate: { duration: 20, repeat: Infinity, ease: 'linear' }
            }}
          />

          <div className="relative bg-gray-900 rounded-2xl p-8 border border-gray-800">
            <motion.h2
              variants={fadeIn}
              className="text-3xl font-bold text-center mb-8 bg-gradient-to-r from-cyan-400 to-purple-600 bg-clip-text text-transparent"
            >
              CyberSec AI Platform
            </motion.h2>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white"
                  required
                />
              </div>

              {!isLogin && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Email
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white"
                    required={!isLogin}
                  />
                </motion.div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white"
                  required
                />
              </div>

              <motion.button
                type="submit"
                disabled={isLoading}
                className="w-full py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-lg disabled:opacity-50"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                {isLoading ? 'Loading...' : isLogin ? 'Login' : 'Register'}
              </motion.button>
            </form>

            <div className="mt-6 text-center">
              <button
                onClick={() => setIsLogin(!isLogin)}
                className="text-blue-400 hover:text-blue-300 text-sm"
              >
                {isLogin ? "Don't have an account? Register" : 'Already have an account? Login'}
              </button>
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}
