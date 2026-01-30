import { createBrowserRouter, Navigate, Outlet } from 'react-router';
import { useAuth } from './context/AuthContext';
import App from './App';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { ForgotPasswordPage } from './pages/ForgotPasswordPage';
import { ResetPasswordPage } from './pages/ResetPasswordPage';
import { DashboardPage } from './pages/DashboardPage';
import { SettingsPage } from './pages/SettingsPage';

function ProtectedRoute() {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return <Outlet />;
}

function GuestRoute() {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user) return <Navigate to="/" replace />;
  return <Outlet />;
}

export const router = createBrowserRouter([
  {
    element: <App />,
    children: [
      {
        element: <ProtectedRoute />,
        children: [
          { path: '/', element: <DashboardPage /> },
          { path: '/settings', element: <SettingsPage /> },
        ],
      },
      {
        element: <GuestRoute />,
        children: [
          { path: '/login', element: <LoginPage /> },
          { path: '/register', element: <RegisterPage /> },
          { path: '/forgot-password', element: <ForgotPasswordPage /> },
          { path: '/reset-password', element: <ResetPasswordPage /> },
        ],
      },
    ],
  },
]);
