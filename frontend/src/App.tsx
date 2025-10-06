import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { useState, useEffect } from 'react'
import { ToastSystem } from './components/ToastSystem'
import { ProgressLoader } from './components/ProgressLoader'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import PortScanner from './pages/PortScanner'
import WebScanner from './pages/WebScanner'
import AIChat from './pages/AIChat'
import CVEDatabase from './pages/CVEDatabase'
import ShodanIntelligence from './pages/ShodanIntelligence'
import ExploitDatabase from './pages/ExploitDatabase'
import Reports from './pages/Reports'
import Billing from './pages/Billing'
import Layout from './components/Layout'

function AnimatedRoutes() {
  const location = useLocation()
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'))
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    const token = localStorage.getItem('token')
    setIsAuthenticated(!!token)
  }, [])

  return (
    <>
      <ProgressLoader isLoading={isLoading} />
      <AnimatePresence mode="wait">
        <Routes location={location} key={location.pathname}>
          <Route
            path="/login"
            element={
              isAuthenticated ? (
                <Navigate to="/" replace />
              ) : (
                <Login onLogin={() => setIsAuthenticated(true)} />
              )
            }
          />
          <Route
            path="/"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <Dashboard />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/port-scanner"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <PortScanner />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/web-scanner"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <WebScanner />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/ai-chat"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <AIChat />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/cve-database"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <CVEDatabase />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/shodan"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <ShodanIntelligence />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/exploits"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <ExploitDatabase />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/reports"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <Reports />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/billing"
            element={
              isAuthenticated ? (
                <Layout setIsLoading={setIsLoading}>
                  <Billing />
                </Layout>
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
        </Routes>
      </AnimatePresence>
    </>
  )
}

function App() {
  return (
    <BrowserRouter>
      <ToastSystem />
      <AnimatedRoutes />
    </BrowserRouter>
  )
}

export default App
