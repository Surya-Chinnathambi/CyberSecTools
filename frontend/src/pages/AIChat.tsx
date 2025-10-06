import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { chatAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { PaperAirplaneIcon } from '@heroicons/react/24/solid'
import { staggerContainer, staggerItem, slideUp } from '@/utils/animations'

interface Message {
  role: 'user' | 'assistant'
  content: string
}

export default function AIChat() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = async () => {
    if (!input.trim()) return

    const userMessage = { role: 'user' as const, content: input }
    setMessages(prev => [...prev, userMessage])
    setInput('')
    setIsLoading(true)

    try {
      const response = await chatAPI.sendMessage(input, undefined, messages)
      const assistantMessage = { role: 'assistant' as const, content: response.data.response }
      setMessages(prev => [...prev, assistantMessage])
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to get response')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="visible"
      className="h-[calc(100vh-8rem)] flex flex-col"
    >
      <motion.div variants={staggerItem} className="mb-6">
        <h1 className="text-4xl font-bold text-white mb-2">AI Security Assistant</h1>
        <p className="text-gray-400">Get AI-powered security analysis and recommendations</p>
      </motion.div>

      <motion.div
        variants={staggerItem}
        className="flex-1 bg-gray-900/50 rounded-lg border border-gray-800 p-4 overflow-y-auto mb-4"
      >
        <AnimatePresence initial={false}>
          {messages.map((msg, idx) => (
            <motion.div
              key={idx}
              variants={slideUp}
              initial="hidden"
              animate="visible"
              className={`mb-4 flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] p-4 rounded-lg ${
                  msg.role === 'user'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-800 text-gray-100'
                }`}
              >
                <p className="whitespace-pre-wrap">{msg.content}</p>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>

        {isLoading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex justify-start"
          >
            <div className="bg-gray-800 text-gray-100 p-4 rounded-lg">
              <div className="flex gap-2">
                <motion.div
                  className="w-2 h-2 bg-blue-500 rounded-full"
                  animate={{ y: [0, -8, 0] }}
                  transition={{ duration: 0.6, repeat: Infinity, delay: 0 }}
                />
                <motion.div
                  className="w-2 h-2 bg-blue-500 rounded-full"
                  animate={{ y: [0, -8, 0] }}
                  transition={{ duration: 0.6, repeat: Infinity, delay: 0.2 }}
                />
                <motion.div
                  className="w-2 h-2 bg-blue-500 rounded-full"
                  animate={{ y: [0, -8, 0] }}
                  transition={{ duration: 0.6, repeat: Infinity, delay: 0.4 }}
                />
              </div>
            </div>
          </motion.div>
        )}

        <div ref={messagesEndRef} />
      </motion.div>

      <motion.div variants={staggerItem} className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSend()}
          placeholder="Ask about security vulnerabilities, best practices, or analysis..."
          className="flex-1 px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
          disabled={isLoading}
        />
        <motion.button
          onClick={handleSend}
          disabled={isLoading || !input.trim()}
          className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-lg disabled:opacity-50"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <PaperAirplaneIcon className="w-5 h-5" />
        </motion.button>
      </motion.div>
    </motion.div>
  )
}
