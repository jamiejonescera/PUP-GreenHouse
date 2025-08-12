import React, { useState, useEffect, createContext, useContext } from 'react';
import { Plus, Search, User, LogOut, MapPin, Clock, MessageSquare, Check, X, Edit, Trash2, Shield } from 'lucide-react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';

// Auth Context
const AuthContext = createContext();

// STEP 1: Add this RIGHT AFTER your AuthContext (around line 60 in App.js)

// Add this AFTER the AuthProvider component:
const NotificationContext = createContext();

const NotificationProvider = ({ children }) => {
  const [notifications, setNotifications] = useState([]);
  const [confirmDialog, setConfirmDialog] = useState(null);
  const [promptDialog, setPromptDialog] = useState(null);

  const showSuccess = (message) => {
    const id = Date.now();
    setNotifications(prev => [...prev, { id, type: 'success', message }]);
    setTimeout(() => removeNotification(id), 3000);
  };

  const showError = (message) => {
    const id = Date.now();
    setNotifications(prev => [...prev, { id, type: 'error', message }]);
    setTimeout(() => removeNotification(id), 5000);
  };

  const showConfirm = (title, message) => {
    return new Promise((resolve) => {
      setConfirmDialog({
        title,
        message,
        onConfirm: () => {
          setConfirmDialog(null);
          resolve(true);
        },
        onCancel: () => {
          setConfirmDialog(null);
          resolve(false);
        }
      });
    });
  };

  const showPrompt = (title, message, placeholder = '') => {
    return new Promise((resolve) => {
      setPromptDialog({
        title,
        message,
        placeholder,
        onConfirm: (value) => {
          setPromptDialog(null);
          resolve(value);
        },
        onCancel: () => {
          setPromptDialog(null);
          resolve(null);
        }
      });
    });
  };

  const removeNotification = (id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  return (
    <NotificationContext.Provider value={{ showSuccess, showError, showConfirm, showPrompt }}>
      {children}
      
      {/* Toast Notifications */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {notifications.map(notification => (
          <div
            key={notification.id}
            className={`p-4 rounded-lg shadow-lg max-w-sm ${
              notification.type === 'success' ? 'bg-green-500 text-white' :
              notification.type === 'error' ? 'bg-red-500 text-white' :
              'bg-gray-500 text-white'
            }`}
          >
            <div className="flex items-start justify-between">
              <p className="text-sm">{notification.message}</p>
              <button
                onClick={() => removeNotification(notification.id)}
                className="ml-2 text-white hover:text-gray-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Custom Confirm Dialog */}
      {confirmDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <h3 className="text-lg font-semibold text-gray-800 mb-2">
              {confirmDialog.title}
            </h3>
            <p className="text-gray-600 mb-6">{confirmDialog.message}</p>
            <div className="flex space-x-3">
              <button
                onClick={confirmDialog.onConfirm}
                className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors"
              >
                Yes
              </button>
              <button
                onClick={confirmDialog.onCancel}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Custom Prompt Dialog */}
      {promptDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <h3 className="text-lg font-semibold text-gray-800 mb-2">
              {promptDialog.title}
            </h3>
            <p className="text-gray-600 mb-4">{promptDialog.message}</p>
            <input
              id="prompt-input"
              type="text"
              placeholder={promptDialog.placeholder}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500 mb-6"
              autoFocus
            />
            <div className="flex space-x-3">
              <button
                onClick={() => {
                  const input = document.getElementById('prompt-input');
                  promptDialog.onConfirm(input.value);
                }}
                className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors"
              >
                OK
              </button>
              <button
                onClick={promptDialog.onCancel}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </NotificationContext.Provider>
  );
};

const useNotification = () => useContext(NotificationContext);

// STEP 2: Find your EcoPantryApp component (at the very bottom) and change it to:


const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [isAdmin, setIsAdmin] = useState(localStorage.getItem('isAdmin') === 'true');
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);
  const [termsContent, setTermsContent] = useState('');
  const [hasAcceptedTerms, setHasAcceptedTerms] = useState(false);
  
  useEffect(() => {
    if (token) {
      try {
        // Decode JWT to get admin status (secure way)
        const payload = JSON.parse(atob(token.split('.')[1]));
        const adminStatus = payload.is_admin || false;
        
        const userData = localStorage.getItem('user');
        if (userData) {
          setUser(JSON.parse(userData));
          setIsAdmin(adminStatus);
        }
      } catch (error) {
        console.error('Invalid token:', error);
        logout();
      }
    }
  }, [token]);

  const login = (userData, authToken, adminStatus = false) => {
    setUser(userData);
    setToken(authToken);
    setIsAdmin(adminStatus);
    localStorage.setItem('token', authToken);
    localStorage.setItem('user', JSON.stringify(userData));
    localStorage.setItem('isAdmin', adminStatus.toString());
    
    // ✅ Check if user has accepted terms (only for regular users)
    if (!adminStatus) {
      const acceptedTerms = localStorage.getItem(`terms_accepted_${userData.user_id || userData.google_id}`);
      if (!acceptedTerms) {
        // First-time user - show terms
        fetchTermsContent();
        setShowTermsModal(true);
      }
    }
  };

  // ✅ Fetch terms content from backend
  const fetchTermsContent = async () => {
    try {
      const response = await fetch(`${API_BASE}/terms-content`);
      const result = await response.json();
      setTermsContent(result.content || 'Default Terms and Conditions content...');
    } catch (error) {
      console.error('Error fetching terms:', error);
      setTermsContent('By using this app, you agree to our terms and conditions.');
    }
  };

  // ✅ Accept terms function
  const acceptTerms = () => {
    const userId = user?.user_id || user?.google_id;
    if (userId) {
      localStorage.setItem(`terms_accepted_${userId}`, 'true');
      setShowTermsModal(false);
      setHasAcceptedTerms(true);
    }
  };

  // ✅ Decline terms function
  const declineTerms = () => {
    // Log them out if they decline
    confirmLogout();
  };

  // ✅ Show logout confirmation modal
  const logout = () => {
    setShowLogoutModal(true);
  };
  
  // ✅ Actually log out
  const confirmLogout = () => {
    setUser(null);
    setToken(null);
    setIsAdmin(false);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('isAdmin');
    setShowLogoutModal(false);
  };

  // ✅ Cancel logout
  const cancelLogout = () => {
    setShowLogoutModal(false);
  };

  return (
    <>
      <AuthContext.Provider value={{ 
        user, 
        token, 
        isAdmin, 
        login, 
        logout, 
        confirmLogout, 
        cancelLogout, 
        showLogoutModal,
        showTermsModal, 
        setShowTermsModal,
        termsContent,
        setTermsContent,
        acceptTerms,
        declineTerms,
        hasAcceptedTerms
      }}>
        {children}
      </AuthContext.Provider>
      
      {/* ✅ LOGOUT CONFIRMATION MODAL */}
      {showLogoutModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <div className="flex items-center mb-4">
              <LogOut className="w-6 h-6 text-red-500 mr-3" />
              <h3 className="text-lg font-semibold text-gray-800">Confirm Logout</h3>
            </div>
            <p className="text-gray-600 mb-6">
              Are you sure you want to log out? You'll need to sign in again to access your account.
            </p>
            <div className="flex space-x-3">
              <button
                onClick={confirmLogout}
                className="flex-1 bg-red-600 text-white py-2 px-4 rounded-lg hover:bg-red-700 transition-colors"
              >
                Yes, Log Out
              </button>
              <button
                onClick={cancelLogout}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ✅ TERMS AND CONDITIONS MODAL */}
      {showTermsModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-lg w-full mx-4 shadow-xl max-h-[80vh] overflow-y-auto">
            <div className="flex items-center mb-4">
              <Shield className="w-6 h-6 text-green-600 mr-3" />
              <h3 className="text-lg font-semibold text-gray-800">Terms and Conditions</h3>
            </div>
            <div className="mb-6 p-4 bg-gray-50 rounded-lg max-h-60 overflow-y-auto">
              <p className="text-gray-700 whitespace-pre-wrap">{termsContent}</p>
            </div>
            <p className="text-sm text-gray-600 mb-6">
              You must accept these terms and conditions to continue using Project GreenHouse.
            </p>
            <div className="flex space-x-3">
              <button
                onClick={acceptTerms}
                className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors"
              >
                I Accept
              </button>
              <button
                onClick={declineTerms}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
              >
                Decline
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};


const useAuth = () => useContext(AuthContext);

const API_BASE = process.env.REACT_APP_API_URL || (
  process.env.NODE_ENV === 'development' 
    ? 'http://localhost:8000'
    : 'https://grcal5qmrihig54qfyc37tzyxe0knzdz.lambda-url.ap-northeast-1.on.aws'
);

console.log('🔍 Current API_BASE:', API_BASE); // Debug line
console.log('🌍 Environment:', process.env.NODE_ENV); // Debug line
const apiService = {
  // Auth endpoints
  googleLogin: async (userData) => {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });
    return response.json();
  },

  adminLogin: async (credentials) => {
    const formData = new FormData();
    formData.append('username', credentials.username);
    formData.append('password', credentials.password);
    
    const response = await fetch(`${API_BASE}/auth/admin/login`, {
      method: 'POST',
      body: formData
    });
    return response.json();
  },

  // Items endpoints
  getItems: async (filters = {}) => {
    const params = new URLSearchParams(filters);
    const response = await fetch(`${API_BASE}/items?${params}`);
    return response.json();
  },

  createItem: async (itemData, token) => {
    const formData = new FormData();
    Object.keys(itemData).forEach(key => {
      if (key === 'images' && itemData[key]) {
        Array.from(itemData[key]).forEach(file => formData.append('images', file));
      } else {
        formData.append(key, itemData[key]);
      }
    });

    const response = await fetch(`${API_BASE}/items`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: formData
    });
    return response.json();
  },

  updateItem: async (itemId, itemData, token) => {
    const response = await fetch(`${API_BASE}/items/${itemId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(itemData)
    });
    return response.json();
  },

  deleteItem: async (itemId, token) => {
    const response = await fetch(`${API_BASE}/items/${itemId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  claimItem: async (itemId, token) => {
    const response = await fetch(`${API_BASE}/items/${itemId}/claim`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  getMyClaims: async (token) => {
    const response = await fetch(`${API_BASE}/my-claims`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  completeItem: async (itemId, token) => {
    const response = await fetch(`${API_BASE}/items/${itemId}/complete`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  // Chat endpoints
  getChatMessages: async (itemId, token) => {
    const response = await fetch(`${API_BASE}/items/${itemId}/chat/messages`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  sendChatMessage: async (itemId, message, token) => {
    const response = await fetch(`${API_BASE}/items/${itemId}/chat/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ message })
    });
    return response.json();
  },

  // Admin endpoints
  getUsers: async (token) => {
    const response = await fetch(`${API_BASE}/users`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  updateUserStatus: async (googleId, isActive, token) => {
    const response = await fetch(`${API_BASE}/users/${googleId}/status?is_active=${isActive}`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  deleteUser: async (googleId, token) => {
    try {
      const response = await fetch(`${API_BASE}/admin/users/${googleId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Failed to delete user');
      return result;
    } catch (error) {
      console.error('Delete user error:', error);
      throw error;
    }
  },

  getPendingItems: async (token) => {
    const response = await fetch(`${API_BASE}/admin/items/pending`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  approveItem: async (itemId, token) => {
    const response = await fetch(`${API_BASE}/admin/items/${itemId}/approve`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  rejectItem: async (itemId, reason, token) => {
    const response = await fetch(`${API_BASE}/admin/items/${itemId}/reject`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ reason })
    });
    return response.json();
  },

  // Locations and categories
  getLocations: async () => {
    const response = await fetch(`${API_BASE}/locations`);
    return response.json();
  },

  createLocation: async (locationData, token) => {
    const response = await fetch(`${API_BASE}/admin/locations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(locationData)
    });
    return response.json();
  },
  deleteLocation: async (locationId, token) => {
    try {
      const response = await fetch(`${API_BASE}/admin/locations/${locationId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Failed to delete location');
      return result;
    } catch (error) {
      console.error('Delete location error:', error);
      throw error;
    }
  },

  getTermsContent: async () => {
    try {
      const response = await fetch(`${API_BASE}/terms-content`);
      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Get terms error:', error);
      throw error;
    }
  },
  
  updateTermsContent: async (content, token) => {
    try {
      const response = await fetch(`${API_BASE}/admin/terms-content`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ content })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Failed to update terms');
      return result;
    } catch (error) {
      console.error('Update terms error:', error);
      throw error;
    }
  },
  
  // ✅ ADD THESE NEW API FUNCTIONS:
  getApprovedItems: async (token) => {
    try {
      const response = await fetch(`${API_BASE}/admin/items/approved`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Get approved items error:', error);
      throw error;
    }
  },

  getRejectedItems: async (token) => {
    try {
      const response = await fetch(`${API_BASE}/admin/items/rejected`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Get rejected items error:', error);
      throw error;
    }
  },


  getCategories: async () => {
    const response = await fetch(`${API_BASE}/categories`);
    return response.json();
  }
};

// Google OAuth Component
// Google OAuth Component - FIXED VERSION
const GoogleLoginButton = ({ onSuccess, onError }) => {
  useEffect(() => {
    const initializeGoogleSignIn = () => {
      if (window.google) {
        window.google.accounts.id.initialize({
          client_id: "740603627895-39r4nspre969ll50ehr4ele2isnn24du.apps.googleusercontent.com",
          callback: handleCredentialResponse
        });
        
        window.google.accounts.id.renderButton(
          document.getElementById("googleSignInButton"),
          { theme: "outline", size: "large", width: "100%" }
        );
      }
    };

    const handleCredentialResponse = async (response) => {
      try {
        console.log('Google credential response received');
        const decoded = JSON.parse(atob(response.credential.split('.')[1]));
        console.log('Decoded Google user:', decoded);
        
        const userData = {
          email: decoded.email,
          name: decoded.name,
          google_id: decoded.sub,
          profile_picture: decoded.picture
        };
        
        console.log('Sending login request with:', userData);
        const result = await apiService.googleLogin(userData);
        console.log('Login result:', result);
        
        if (result.access_token) {
          // Create user object that matches what your app expects
          const userForApp = {
            ...userData,
            user_id: result.user?.user_id || userData.google_id,
            email: result.user?.email || userData.email,
            name: result.user?.name || userData.name
          };
          onSuccess(userForApp, result.access_token);
        } else {
          onError('Login failed: Sorry You Have Been Reported for Pranking a User');
        }
      } catch (error) {
        console.error('Google login error:', error);
        onError('Google login failed: ' + error.message);
      }
    };

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = initializeGoogleSignIn;
    document.head.appendChild(script);

    return () => {
      const existingScript = document.querySelector('script[src="https://accounts.google.com/gsi/client"]');
      if (existingScript) {
        document.head.removeChild(existingScript);
      }
    };
  }, [onSuccess, onError]);

  return <div id="googleSignInButton"></div>;
};




// User Login Component (Google OAuth only)
const UserLogin = () => {
  const { login } = useAuth();
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleGoogleLogin = async (userData, token) => {
    try {
      console.log('Google login success:', userData);
      login(userData, token, false);
      navigate('/dashboard'); // Redirect to user dashboard
    } catch (error) {
      console.error('Google login error:', error);
      setError('Google login failed: ' + error.message);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-8">
        {/* User Header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold text-green-800 mb-2">Project GreenHouse</h1>
          <p className="text-gray-600">Sustainable Exchange Platform for PUP Community</p>
          <p className="text-sm text-green-600 font-medium mt-2">Student & Faculty Portal</p>
        </div>

        {/* Error Display */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg">
            <div className="flex items-center">
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              {error}
            </div>
          </div>
        )}

        {/* Google Login */}
        <div className="space-y-6">
          <div className="text-center">
            <p className="text-gray-600 mb-4">Sign in with your Google account</p>
          </div>

            <div className="flex justify-center">
              <GoogleLoginButton 
                onSuccess={handleGoogleLogin}
                onError={setError}
              />
            </div>
          {/* Features List */}
          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <h3 className="text-sm font-semibold text-gray-700 mb-2">What you can do:</h3>
            <ul className="text-xs text-gray-600 space-y-1">
              <li>• Share items with the PUP community</li>
              <li>• Claim items from other students</li>
              <li>• Chat with item owners</li>
              <li>• Help reduce waste on campus</li>
            </ul>
          </div>
        </div>

        {/* Clean footer - NO admin links */}
        <div className="mt-8 pt-6 border-t border-gray-200 text-center">
          <p className="text-xs text-gray-300">© 2025 Project GreenHouse</p>
        </div>
      </div>
    </div>
  );
};

// Secret Admin Login Component
// Add these new components to your App.js file

// 1. REPLACE your existing AdminLogin component with this enhanced version:

const AdminLogin = () => {
  const { login } = useAuth();
  const [adminCredentials, setAdminCredentials] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSetup, setShowSetup] = useState(false);
  const [checkingSetup, setCheckingSetup] = useState(true);
  const navigate = useNavigate();

  // Check if admin setup is needed
  useEffect(() => {
    checkAdminSetup();
  }, []);

  const checkAdminSetup = async () => {
    try {
      const response = await fetch(`${API_BASE}/admin/setup/check`);
      const result = await response.json();
      setShowSetup(result.first_time_setup);
    } catch (error) {
      console.error('Error checking admin setup:', error);
      setShowSetup(true); // Assume setup needed if error
    } finally {
      setCheckingSetup(false);
    }
  };

  const handleAdminLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      console.log('Attempting new admin login...');
      const response = await fetch(`${API_BASE}/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(adminCredentials)
      });
      
      const result = await response.json();
      
      if (response.ok && result.access_token) {
        const adminUser = {
          name: result.user?.name || 'Administrator',
          email: result.user?.email || adminCredentials.email,
          user_id: result.user?.user_id || 'admin-user-001',
          google_id: result.user?.user_id || 'admin-user-001'
        };
        login(adminUser, result.access_token, true);
        navigate('/admin-portal');
      } else {
        setError(result.error || result.detail || 'Login failed');
      }
    } catch (error) {
      console.error('Admin login error:', error);
      setError('Login failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  if (checkingSetup) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-700 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white"></div>
      </div>
    );
  }

  if (showSetup) {
    return <AdminSetup onSetupComplete={() => setShowSetup(false)} />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-700 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        {/* Admin Header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-red-600" />
          </div>
          <h1 className="text-2xl font-bold text-gray-800 mb-2">Project GreenHouse</h1>
          <p className="text-gray-600">Admin Portal</p>
          <div className="mt-2 px-3 py-1 bg-red-100 text-red-800 text-xs font-medium rounded-full inline-block">
            Polytechnic University of the Philippines
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg">
            <div className="flex items-center">
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              {error}
            </div>
          </div>
        )}

        {/* Admin Login Form */}
        <form onSubmit={handleAdminLogin} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <input
              type="email"
              value={adminCredentials.email}
              onChange={(e) => setAdminCredentials({...adminCredentials, email: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
              required
              disabled={loading}
              placeholder="Enter admin email"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <input
              type="password"
              value={adminCredentials.password}
              onChange={(e) => setAdminCredentials({...adminCredentials, password: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
              required
              disabled={loading}
              placeholder="Enter admin password"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-red-600 text-white py-3 px-4 rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Signing in...
              </span>
            ) : (
              <span className="flex items-center justify-center">
                <Shield className="w-5 h-5 mr-2" />
                Admin Login
              </span>
            )}
          </button>

          {/* Forgot Password Link */}
          <div className="text-center">
            <button
              type="button"
              onClick={() => navigate('/admin-forgot-password')}
              className="text-red-600 hover:text-red-800 text-sm transition-colors"
            >
              Forgot your password?
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// 2. ADD this new AdminSetup component:

const AdminSetup = ({ onSetupComplete }) => {
  const [setupData, setSetupData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSetup = async (e) => {
    e.preventDefault();
    setError('');

    // Validation
    if (setupData.password !== setupData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (setupData.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/admin/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: setupData.name,
          email: setupData.email,
          password: setupData.password
        })
      });

      const result = await response.json();

      if (result.success) {
        alert('Admin account created successfully! You can now log in.');
        onSetupComplete();
      } else {
        setError(result.error || 'Setup failed');
      }
    } catch (error) {
      console.error('Setup error:', error);
      setError('Setup failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 to-purple-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-blue-600" />
          </div>
          <h1 className="text-2xl font-bold text-gray-800 mb-2">First-Time Setup</h1>
          <p className="text-gray-600">Create your admin account for Project GreenHouse</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSetup} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Full Name *
            </label>
            <input
              type="text"
              value={setupData.name}
              onChange={(e) => setSetupData({...setupData, name: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
              disabled={loading}
              placeholder="Enter your full name"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email Address *
            </label>
            <input
              type="email"
              value={setupData.email}
              onChange={(e) => setSetupData({...setupData, email: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
              disabled={loading}
              placeholder="Enter admin email"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password *
            </label>
            <input
              type="password"
              value={setupData.password}
              onChange={(e) => setSetupData({...setupData, password: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
              disabled={loading}
              placeholder="Create a strong password"
              minLength={8}
            />
            <p className="text-xs text-gray-500 mt-1">Must be at least 8 characters with uppercase, lowercase, and numbers</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Confirm Password *
            </label>
            <input
              type="password"
              value={setupData.confirmPassword}
              onChange={(e) => setSetupData({...setupData, confirmPassword: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
              disabled={loading}
              placeholder="Confirm your password"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 font-medium mt-6"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Creating Account...
              </span>
            ) : (
              'Create Admin Account'
            )}
          </button>
        </form>

        <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
          <div className="flex items-start">
            <svg className="w-5 h-5 text-yellow-600 mr-2 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <div>
              <p className="text-yellow-800 text-sm font-medium">Important</p>
              <p className="text-yellow-700 text-xs mt-1">
                This will be the only admin account. Keep your credentials secure!
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// 3. ADD this AdminProfile component (to be used in AdminDashboard):

const AdminProfile = ({ onClose }) => {
  const { user, token } = useAuth();
  const [profileData, setProfileData] = useState({
    current_email: user?.email || '',
    new_name: user?.name || '',
    new_email: user?.email || '',
    new_password: '',
    confirm_password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (profileData.new_password && profileData.new_password !== profileData.confirm_password) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      const updateData = {
        current_email: profileData.current_email,
        new_name: profileData.new_name !== user?.name ? profileData.new_name : null,
        new_email: profileData.new_email !== user?.email ? profileData.new_email : null,
        new_password: profileData.new_password || null
      };

      // Remove null values
      Object.keys(updateData).forEach(key => {
        if (updateData[key] === null) delete updateData[key];
      });

      const response = await fetch(`${API_BASE}/admin/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(updateData)
      });

      const result = await response.json();

      if (result.success) {
        setSuccess('Profile updated successfully!');
        setTimeout(() => {
          onClose();
          // You might want to refresh the page or update the user context here
        }, 2000);
      } else {
        setError(result.error || 'Update failed');
      }
    } catch (error) {
      console.error('Profile update error:', error);
      setError('Update failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-bold text-gray-800">Admin Profile Settings</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded text-sm">
              {error}
            </div>
          )}

          {success && (
            <div className="mb-4 p-3 bg-green-100 border border-green-400 text-green-700 rounded text-sm">
              {success}
            </div>
          )}

          <form onSubmit={handleUpdateProfile} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Name
              </label>
              <input
                type="text"
                value={profileData.new_name}
                onChange={(e) => setProfileData({...profileData, new_name: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                required
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Email Address
              </label>
              <input
                type="email"
                value={profileData.new_email}
                onChange={(e) => setProfileData({...profileData, new_email: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                required
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                New Password (optional)
              </label>
              <input
                type="password"
                value={profileData.new_password}
                onChange={(e) => setProfileData({...profileData, new_password: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                disabled={loading}
                placeholder="Leave blank to keep current password"
                minLength={8}
              />
            </div>

            {profileData.new_password && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Confirm New Password
                </label>
                <input
                  type="password"
                  value={profileData.confirm_password}
                  onChange={(e) => setProfileData({...profileData, confirm_password: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                  disabled={loading}
                  placeholder="Confirm new password"
                />
              </div>
            )}

            <div className="flex space-x-3 pt-4">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
              >
                {loading ? (
                  <span className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Updating...
                  </span>
                ) : (
                  'Update Profile'
                )}
              </button>
              <button
                type="button"
                onClick={onClose}
                disabled={loading}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};




// ADD these two missing components before your App component:

const AdminForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/admin/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const result = await response.json();

      if (result.success) {
        setSuccess(true);
      } else {
        setError(result.error || 'Failed to send reset email');
      }
    } catch (error) {
      console.error('Forgot password error:', error);
      setError('Failed to send reset email');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-700 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
          <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-800 mb-4">Check Your Email</h2>
          <p className="text-gray-600 mb-6">
            Password reset link has been sent to the admin's email account.
          </p>
          <button
            onClick={() => navigate('/admin-portal-xyz123')}
            className="w-full bg-gray-600 text-white py-3 px-4 rounded-lg hover:bg-gray-700 transition-colors"
          >
            Back to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-700 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m0 0a2 2 0 012 2v6a2 2 0 01-2 2H7a2 2 0 01-2-2V9a2 2 0 012-2m0 0V7a2 2 0 012-2m4 0V5a2 2 0 00-2-2H9a2 2 0 00-2 2v2m8 0V9a2 2 0 00-2-2H9a2 2 0 00-2 2v8a2 2 0 002 2h6a2 2 0 002-2V9z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-gray-800 mb-2">Reset Password</h1>
          <p className="text-gray-600">Enter your admin email to receive a reset link</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleForgotPassword} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Admin Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
              disabled={loading}
              placeholder="Enter your admin email"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 font-medium"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Sending Reset Link...
              </span>
            ) : (
              'Send Reset Link'
            )}
          </button>

          <div className="text-center">
            <button
              type="button"
              onClick={() => navigate('/admin-portal-xyz123')}
              className="text-gray-600 hover:text-gray-800 text-sm transition-colors"
            >
              Back to Login
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const AdminResetPassword = () => {
  const [passwords, setPasswords] = useState({
    new_password: '',
    confirm_password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const navigate = useNavigate();
  
  // Get token from URL
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');

  useEffect(() => {
    if (!token) {
      setError('Invalid reset link');
    }
  }, [token]);

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');

    if (passwords.new_password !== passwords.confirm_password) {
      setError('Passwords do not match');
      return;
    }

    if (passwords.new_password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/admin/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          new_password: passwords.new_password
        })
      });

      const result = await response.json();

      if (result.success) {
        setSuccess(true);
      } else {
        setError(result.error || 'Password reset failed');
      }
    } catch (error) {
      console.error('Reset password error:', error);
      setError('Password reset failed');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-700 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
          <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-800 mb-4">Password Reset Successful</h2>
          <p className="text-gray-600 mb-6">
            Your admin password has been reset successfully. You can now log in with your new password.
          </p>
          <button
            onClick={() => navigate('/admin-portal-xyz123')}
            className="w-full bg-green-600 text-white py-3 px-4 rounded-lg hover:bg-green-700 transition-colors"
          >
            Go to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-700 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m0 0a2 2 0 012 2v6a2 2 0 01-2 2H7a2 2 0 01-2-2V9a2 2 0 012-2m0 0V7a2 2 0 012-2m4 0V5a2 2 0 00-2-2H9a2 2 0 00-2 2v2m8 0V9a2 2 0 00-2-2H9a2 2 0 00-2 2v8a2 2 0 002 2h6a2 2 0 002-2V9z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-gray-800 mb-2">Set New Password</h1>
          <p className="text-gray-600">Enter your new admin password</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleResetPassword} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              New Password
            </label>
            <input
              type="password"
              value={passwords.new_password}
              onChange={(e) => setPasswords({...passwords, new_password: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
              required
              disabled={loading}
              placeholder="Enter new password"
              minLength={8}
            />
            <p className="text-xs text-gray-500 mt-1">Must be at least 8 characters</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Confirm New Password
            </label>
            <input
              type="password"
              value={passwords.confirm_password}
              onChange={(e) => setPasswords({...passwords, confirm_password: e.target.value})}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
              required
              disabled={loading}
              placeholder="Confirm new password"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !token}
            className="w-full bg-green-600 text-white py-3 px-4 rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 font-medium"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Resetting Password...
              </span>
            ) : (
              'Reset Password'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};



// Protected Route Component
const ProtectedRoute = ({ children, adminOnly = false }) => {
  const { user, token, isAdmin } = useAuth();

  if (!token || !user) {
    return <Navigate to="/login" replace />;
  }

  if (adminOnly && !isAdmin) {
    return <Navigate to="/login" replace />;
  }

  return children;
};


const ItemCard = ({ item, onClaim, onEdit, onDelete, currentUser, onChatToggle, showChat, chatMessages, onSendMessage, newMessage, setNewMessage }) => {
  const [showClaimModal, setShowClaimModal] = useState(false);
  
  // Fix ownership checking - handle multiple field possibilities
  const isOwner = currentUser && (
    item.owner_email === currentUser.email || 
    item.owner_id === currentUser.user_id ||
    item.owner_id === currentUser.google_id ||
    item.owner_email === currentUser.user_id
  );
  
  const canClaim = !isOwner && item.status === 'available' && item.approved;
  
  // Fix claimed status checking
  const isClaimed = item.status === 'claimed' && (
    isOwner || 
    item.claimant_email === currentUser?.email ||
    item.claimed_by === currentUser?.user_id ||
    item.claimed_by === currentUser?.google_id
  );

  const handleClaim = () => {
    setShowClaimModal(false);
    onClaim(item.item_id);
  };

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      {/* MANDATORY IMAGE DISPLAY - Always show since images are required */}
      <div className="relative">
        {(item.images || item.image_urls) && (item.images || item.image_urls).length > 0 ? (
          <>
            <img 
              src={(item.images || item.image_urls)[0]} 
              alt={item.name} 
              className="w-full h-400 object-cover"
              onError={(e) => {
                // Fallback to placeholder if image fails to load
                e.target.src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZGRkIi8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNCIgZmlsbD0iIzk5OSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZHk9Ii4zZW0iPkltYWdlIE5vdCBGb3VuZDwvdGV4dD48L3N2Zz4=';
                console.log('Image failed to load, using placeholder:', e.target.src);
              }}
            />
            
            {/* Show image count if multiple images */}
            {(item.images || item.image_urls).length > 1 && (
              <div className="absolute top-2 right-2 bg-black bg-opacity-75 text-white text-xs px-2 py-1 rounded-full">
                +{(item.images || item.image_urls).length - 1} more
              </div>
            )}
          </>
        ) : (
          // Fallback placeholder (this shouldn't happen since images are mandatory)
          <div className="w-full h-48 bg-gray-200 flex items-center justify-center">
            <div className="text-center text-gray-500">
              <svg className="w-12 h-12 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
              <span className="text-sm">No Image Available</span>
            </div>
          </div>
        )}
      </div>
      
      <div className="p-4">
        <div className="flex justify-between items-start mb-2">
          <h3 className="text-lg font-semibold text-gray-800">{item.name}</h3>
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
            item.status === 'available' ? 'bg-green-100 text-green-800' :
            item.status === 'claimed' ? 'bg-yellow-100 text-yellow-800' :
            'bg-gray-100 text-gray-800'
          }`}>
            {item.status}
          </span>
        </div>
        
        <p className="text-gray-600 mb-2">Quantity: {item.quantity}</p>
        <p className="text-gray-600 mb-2">Category: {item.category}</p>
        <p className="text-gray-600 mb-2 flex items-center">
          <MapPin className="w-4 h-4 mr-1" />
          {item.location}
        </p>
        
        {item.expiry_date && (
          <p className="text-gray-600 mb-2 flex items-center">
            <Clock className="w-4 h-4 mr-1" />
            Expires: {new Date(item.expiry_date).toLocaleDateString()}
          </p>
        )}
        
        {item.comments && (
          <p className="text-gray-600 mb-3 text-sm italic">"{item.comments}"</p>
        )}
        
        {/* Contact info for claimed items */}
        {item.contact_info && isClaimed && (
          <p className="text-gray-600 mb-3 text-sm">
            <span className="font-medium">Contact:</span> {item.contact_info}
          </p>
        )}
        
        <div className="flex justify-between items-center">
          {isOwner ? (
            <div className="flex space-x-2">
              <button
                onClick={() => onEdit(item)}
                className="flex items-center px-3 py-1 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 transition-colors"
              >
                <Edit className="w-4 h-4 mr-1" />
                Edit
              </button>
              <button
                onClick={() => onDelete(item.item_id)}
                className="flex items-center px-3 py-1 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 transition-colors"
              >
                <Trash2 className="w-4 h-4 mr-1" />
                Delete
              </button>
            </div>
          ) : canClaim ? (
            <button
              onClick={() => setShowClaimModal(true)}
              className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <Check className="w-4 h-4 mr-1" />
              Claim This Item
            </button>
          ) : null}
          
          {isClaimed && (
            <button
              onClick={() => onChatToggle(item.item_id)}
              className="flex items-center px-3 py-1 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 transition-colors"
            >
              <MessageSquare className="w-4 h-4 mr-1" />
              Chat
            </button>
          )}
        </div>
        
        {showChat && isClaimed && (
          <div className="mt-4 border-t pt-4">
            <div className="h-32 overflow-y-auto mb-2 bg-gray-50 p-2 rounded border">
              {chatMessages && chatMessages.length > 0 ? (
                chatMessages.map((msg, index) => {
                  const isMyMessage = msg.sender_email === currentUser?.email || 
                                    msg.sender_id === currentUser?.user_id ||
                                    msg.sender_id === currentUser?.google_id;
                  
                  return (
                    <div key={index} className={`mb-2 ${isMyMessage ? 'text-right' : 'text-left'}`}>
                      <div className={`inline-block p-2 rounded-lg max-w-xs ${
                        isMyMessage ? 'bg-green-600 text-white' : 'bg-white text-gray-800 border'
                      }`}>
                        <p className="text-sm">{msg.message}</p>
                        <p className="text-xs opacity-75">
                          {new Date(msg.timestamp || msg.created_at).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                  );
                })
              ) : (
                <p className="text-gray-500 text-sm text-center py-4">No messages yet</p>
              )}
            </div>
            <div className="flex">
              <input
                type="text"
                value={newMessage || ''}
                onChange={(e) => setNewMessage(e.target.value)}
                placeholder="Type a message..."
                className="flex-1 px-3 py-2 border border-gray-300 rounded-l-lg focus:outline-none focus:border-green-500"
                onKeyPress={(e) => e.key === 'Enter' && onSendMessage()}
              />
              <button
                onClick={onSendMessage}
                className="px-4 py-2 bg-green-600 text-white rounded-r-lg hover:bg-green-700 transition-colors"
              >
                Send
              </button>
            </div>
          </div>
        )}
      </div>
      
      {showClaimModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg max-w-sm w-full mx-4 shadow-xl">
            <h3 className="text-lg font-bold mb-4 text-gray-900">Claim This Item</h3>
            <p className="text-gray-600 mb-4">
              You must claim this item - no cancellations! Are you sure you want to proceed?
            </p>
            <div className="flex space-x-3">
              <button
                onClick={handleClaim}
                className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors"
              >
                Yes, Claim It
              </button>
              <button
                onClick={() => setShowClaimModal(false)}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Add/Edit Item Modal
const ItemModal = ({ isOpen, onClose, item, onSave, locations, categories }) => {
  const [formData, setFormData] = useState({
    name: '',
    quantity: 1,
    category: '',
    location: '',
    expiry_date: '',
    duration_days: 7,
    comments: '',
    contact_info: '',
    images: null
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});

  // ✅ FIX: Add useEffect to populate form when editing
  useEffect(() => {
    if (item && isOpen) {
      // Populate form with existing item data
      setFormData({
        name: item.name || '',
        quantity: item.quantity || 1,
        category: item.category || '',
        location: item.location || '',
        expiry_date: item.expiry_date ? item.expiry_date.split('T')[0] : '', // Format date for input
        duration_days: item.duration_days || 7,
        comments: item.comments || '',
        contact_info: item.contact_info || '',
        images: null // Can't pre-populate file input
      });
      setErrors({}); // Clear any previous errors
    } else if (!item && isOpen) {
      // Reset form for new items
      setFormData({
        name: '',
        quantity: 1,
        category: '',
        location: '',
        expiry_date: '',
        duration_days: 7,
        comments: '',
        contact_info: '',
        images: null
      });
      setErrors({});
    }
  }, [item, isOpen]);

  // Validation function
  const validateForm = () => {
    const newErrors = {};

    // Name validation
    if (!formData.name || !formData.name.trim()) {
      newErrors.name = 'Item name is required';
    }

    // Category validation
    if (!formData.category) {
      newErrors.category = 'Category is required';
    }

    // Location validation
    if (!formData.location) {
      newErrors.location = 'Location is required';
    }

    // Expiry date validation
    if (!formData.expiry_date) {
      newErrors.expiry_date = 'Expiry date is required';
    } else {
      // Check if date is not in the past
      const selectedDate = new Date(formData.expiry_date);
      const today = new Date();
      today.setHours(0, 0, 0, 0); // Reset time for accurate comparison
      
      if (selectedDate < today) {
        newErrors.expiry_date = 'Expiry date cannot be in the past';
      }
    }

    // Comments validation
    if (!formData.comments || !formData.comments.trim()) {
      newErrors.comments = 'Description is required';
    } else if (formData.comments.trim().length < 10) {
      newErrors.comments = 'Description must be at least 10 characters';
    }

    // Contact info validation
    if (!formData.contact_info || !formData.contact_info.trim()) {
      newErrors.contact_info = 'Contact information is required';
    }

    // Images validation (only for new items)
    if (!item && (!formData.images || formData.images.length === 0)) {
      newErrors.images = 'At least one image is required';
    }

    // Quantity validation
    if (!formData.quantity || formData.quantity < 1) {
      newErrors.quantity = 'Quantity must be at least 1';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validate form
    if (!validateForm()) {
      return; // Stop if validation fails
    }

    setLoading(true);
    
    try {
      await onSave(formData);
      
      // ✅ FIX: Success feedback (you can replace with custom modal later)
      console.log('✅ Item saved successfully!');
      
      // Close modal on success
      onClose();
      
    } catch (error) {
      console.error('❌ Error saving item:', error);
      
      // ✅ FIX: Better error handling (you can replace with custom modal)
      setErrors({ 
        submit: 'Failed to save item: ' + (error.message || 'Unknown error') 
      });
    } finally {
      setLoading(false);
    }
  };

  // Don't render if not open
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-md w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold">{item ? 'Edit Item' : 'Add New Item'}</h2>
            <button 
              onClick={onClose} 
              className="text-gray-500 hover:text-gray-700 transition-colors"
              disabled={loading}
            >
              <X className="w-6 h-6" />
            </button>
          </div>
          
          {/* ✅ FIX: Show submit errors */}
          {errors.submit && (
            <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
              {errors.submit}
            </div>
          )}
          
          <form onSubmit={handleSubmit}>
            {/* Item Name - REQUIRED */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Item Name <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                  errors.name ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                }`}
                required
                disabled={loading}
                placeholder="Enter item name"
                maxLength={100}
              />
              {errors.name && <p className="text-red-500 text-xs mt-1">{errors.name}</p>}
            </div>
            
            {/* Quantity - REQUIRED */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Quantity <span className="text-red-500">*</span>
              </label>
              <input
                type="number"
                min="1"
                max="999"
                value={formData.quantity}
                onChange={(e) => setFormData({...formData, quantity: parseInt(e.target.value) || 1})}
                className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                  errors.quantity ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                }`}
                required
                disabled={loading}
              />
              {errors.quantity && <p className="text-red-500 text-xs mt-1">{errors.quantity}</p>}
            </div>
            
            {/* Category - REQUIRED */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Category <span className="text-red-500">*</span>
              </label>
              <select
                value={formData.category}
                onChange={(e) => setFormData({...formData, category: e.target.value})}
                className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                  errors.category ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                }`}
                required
                disabled={loading}
              >
                <option value="">Select Category</option>
                {categories && categories.length > 0 ? (
                  categories.map(cat => (
                    <option key={cat} value={cat}>{cat}</option>
                  ))
                ) : (
                  <option disabled>Loading categories...</option>
                )}
              </select>
              {errors.category && <p className="text-red-500 text-xs mt-1">{errors.category}</p>}
            </div>
            
            {/* Location - REQUIRED */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Location <span className="text-red-500">*</span>
              </label>
              <select
                value={formData.location}
                onChange={(e) => setFormData({...formData, location: e.target.value})}
                className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                  errors.location ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                }`}
                required
                disabled={loading}
              >
                <option value="">Select Location</option>
                {locations && locations.length > 0 ? (
                  locations.map(loc => (
                    <option key={loc.location_id || loc.name} value={loc.name}>
                      {loc.name}
                    </option>
                  ))
                ) : (
                  <option disabled>Loading locations...</option>
                )}
              </select>
              {errors.location && <p className="text-red-500 text-xs mt-1">{errors.location}</p>}
            </div>
            
            {/* Expiry Date - REQUIRED */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Expiry Date <span className="text-red-500">*</span>
              </label>
              <input
                type="date"
                value={formData.expiry_date}
                onChange={(e) => setFormData({...formData, expiry_date: e.target.value})}
                className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                  errors.expiry_date ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                }`}
                required
                disabled={loading}
                min={new Date().toISOString().split('T')[0]}
              />
              {errors.expiry_date && <p className="text-red-500 text-xs mt-1">{errors.expiry_date}</p>}
            </div>
            
            {/* Duration Days */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Duration (Days) <span className="text-red-500">*</span>
              </label>
              <select
                value={formData.duration_days}
                onChange={(e) => setFormData({...formData, duration_days: parseInt(e.target.value)})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500 transition-colors"
                disabled={loading}
              >
                <option value={1}>1 day</option>
                <option value={3}>3 days</option>
                <option value={7}>1 week</option>
                <option value={14}>2 weeks</option>
                <option value={30}>1 month</option>
              </select>
            </div>
            
            {/* Comments - REQUIRED */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Description/Comments <span className="text-red-500">*</span>
              </label>
              <textarea
                rows="3"
                value={formData.comments}
                onChange={(e) => setFormData({...formData, comments: e.target.value})}
                className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                  errors.comments ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                }`}
                required
                disabled={loading}
                placeholder="Describe the item condition, how to use it, etc. (minimum 10 characters)"
                maxLength={500}
              />
              <div className="flex justify-between items-center mt-1">
                {errors.comments ? (
                  <p className="text-red-500 text-xs">{errors.comments}</p>
                ) : (
                  <p className="text-gray-500 text-xs">Minimum 10 characters</p>
                )}
                <p className="text-gray-400 text-xs">{formData.comments.length}/500</p>
              </div>
            </div>
            
            {/* Contact Info - REQUIRED */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Contact Information <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                placeholder="Phone number, email, or other contact method"
                value={formData.contact_info}
                onChange={(e) => setFormData({...formData, contact_info: e.target.value})}
                className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                  errors.contact_info ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                }`}
                required
                disabled={loading}
                maxLength={100}
              />
              {errors.contact_info && <p className="text-red-500 text-xs mt-1">{errors.contact_info}</p>}
            </div>
            
            {/* Images - REQUIRED for new items */}
            {!item && (
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Images <span className="text-red-500">*</span>
                </label>
                <input
                  type="file"
                  multiple
                  accept="image/jpeg,image/png,image/jpg,image/gif"
                  onChange={(e) => setFormData({...formData, images: e.target.files})}
                  className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                    errors.images ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                  }`}
                  required
                  disabled={loading}
                />
                {errors.images && <p className="text-red-500 text-xs mt-1">{errors.images}</p>}
                <p className="text-xs text-gray-500 mt-1">
                  Upload at least one clear photo. Accepted formats: JPG, PNG, GIF (max 5MB each)
                </p>
              </div>
            )}
            
            <div className="flex space-x-3">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <span className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    {item ? 'Updating...' : 'Adding...'}
                  </span>
                ) : (
                  item ? 'Update Item' : 'Add Item'
                )}
              </button>
              <button
                type="button"
                onClick={onClose}
                disabled={loading}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};


// User Dashboard
const UserDashboard = () => {
  const { user, token, logout } = useAuth();
  const [items, setItems] = useState([]);
  const [filteredItems, setFilteredItems] = useState([]);
  const [locations, setLocations] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingItem, setEditingItem] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState('');
  const [filterLocation, setFilterLocation] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  const [myClaims, setMyClaims] = useState([]);
  const [chatState, setChatState] = useState({});
  const [chatMessages, setChatMessages] = useState({});
  const [newMessages, setNewMessages] = useState({});
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);
  const { showSuccess, showError, showConfirm } = useNotification();
  const [aiRecommendations, setAiRecommendations] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');

  const loadData = React.useCallback(async () => {
    console.log('🔄 Loading data... User:', user?.email, 'Token:', !!token);
    
    try {
      const [itemsRes, locationsRes, categoriesRes, claimsRes] = await Promise.all([
        apiService.getItems({ approved_only: true }),
        apiService.getLocations(),
        apiService.getCategories(),
        apiService.getMyClaims(token)
      ]);
      
      console.log('📊 Data loaded:', {
        items: itemsRes?.length || 0,
        locations: locationsRes?.length || 0, 
        categories: categoriesRes?.length || 0,
        claims: claimsRes?.length || 0
      });
      
      // Ensure arrays with fallbacks
      setItems(Array.isArray(itemsRes) ? itemsRes : []);
      setLocations(Array.isArray(locationsRes) ? locationsRes : []);
      setCategories(Array.isArray(categoriesRes) ? categoriesRes : []);
      setMyClaims(Array.isArray(claimsRes) ? claimsRes : []);
      
      console.log('✅ Data set successfully');
      
    } catch (error) {
      console.error('❌ Error loading data:', error);
      // Set empty arrays on error
      setItems([]);
      setLocations([]);
      setCategories([]);
      setMyClaims([]);
    } finally {
      setLoading(false);
    }
  }, [token]);

  // FIXED: Enhanced filterItems with better user matching
  const filterItems = React.useCallback(() => {
    console.log('🔍 Filtering items...', {
      totalItems: items.length,
      activeTab,
      user: user?.email,
      searchTerm,
      filterCategory,
      filterLocation
    });
    
    let filtered = [...items]; // Create copy to avoid mutations
    
    // Filter by tab
    if (activeTab === 'my-items') {
      filtered = filtered.filter(item => {
        const isMyItem = item.owner_email === user?.email || 
                        item.owner_id === user?.user_id ||
                        item.owner_id === user?.google_id;
        console.log('My item check:', { item: item.name, owner_email: item.owner_email, user_email: user?.email, isMyItem });
        return isMyItem;
      });
    } else if (activeTab === 'claimed') {
      filtered = filtered.filter(item => {
        const isMyClaim = item.claimant_email === user?.email ||
                         item.claimed_by === user?.user_id ||
                         item.claimed_by === user?.google_id;
        console.log('My claim check:', { item: item.name, claimant_email: item.claimant_email, user_email: user?.email, isMyClaim });
        return isMyClaim;
      });
    } else if (activeTab === 'all') {
      // ✅ NEW: Hide my own items from "All Items" tab
      filtered = filtered.filter(item => {
        const isMyItem = item.owner_email === user?.email || 
                        item.owner_id === user?.user_id ||
                        item.owner_id === user?.google_id;
        return !isMyItem; // Show everything EXCEPT my items
      });
    }
    
    // Filter by search term
    if (searchTerm && searchTerm.trim()) {
      const searchLower = searchTerm.toLowerCase();
      filtered = filtered.filter(item =>
        item.name?.toLowerCase().includes(searchLower) ||
        item.comments?.toLowerCase().includes(searchLower) ||
        item.category?.toLowerCase().includes(searchLower)
      );
    }
    
    // Filter by category
    if (filterCategory) {
      filtered = filtered.filter(item => item.category === filterCategory);
    }
    
    // Filter by location
    if (filterLocation) {
      filtered = filtered.filter(item => item.location === filterLocation);
    }
    
    console.log('🎯 Filtering result:', {
      original: items.length,
      filtered: filtered.length,
      activeTab
    });
    
    setFilteredItems(filtered);
  }, [items, searchTerm, filterCategory, filterLocation, activeTab, user?.email, user?.user_id, user?.google_id]);

  // FIXED: Proper useEffect dependencies
  useEffect(() => {
    if (token && user) {
      loadData();
    }
  }, [loadData, token, user]);

  useEffect(() => {
    filterItems();
  }, [filterItems]);

  // FIXED: Enhanced item handlers with better error handling

  const handleAddItem = async (formData) => {
    try {
      const result = await apiService.createItem(formData, token);
      setShowModal(false);
      showSuccess('Item submitted for approval!'); 
      await loadData();
    } catch (error) {
      showError('❌ Failed to add item: ' + error.message);
    }
  };
  
  const handleEditItem = async (formData) => {
    try {
      console.log('✏️ Editing item:', editingItem?.item_id, formData);
      const result = await apiService.updateItem(editingItem.item_id, formData, token);
      console.log('✅ Item updated:', result);
      setShowModal(false);
      setEditingItem(null);
      await loadData(); // Reload data
    } catch (error) {
      console.error('❌ Error updating item:', error);
      alert('Failed to update item: ' + error.message);
    }
  };

  const handleDeleteItem = async (itemId) => {
    const confirmed = await showConfirm('Delete Item', 'Are you sure you want to delete this item?');
    if (confirmed) {
      try {
        await apiService.deleteItem(itemId, token);
        showSuccess('Item deleted successfully');
        await loadData();
      } catch (error) {
        showError('Failed to delete item: ' + error.message);
      }
    }
  };

  const handleClaimItem = async (itemId) => {
    try {
      console.log('🎯 Claiming item:', itemId);
      const result = await apiService.claimItem(itemId, token);
      console.log('✅ Item claimed:', result);
      await loadData(); // Reload data
    } catch (error) {
      console.error('❌ Error claiming item:', error);
      alert('Failed to claim item: ' + error.message);
    }
  };

  const handleChatToggle = async (itemId) => {
    console.log('💬 Toggling chat for item:', itemId);
    
    setChatState(prev => ({
      ...prev,
      [itemId]: !prev[itemId]
    }));

    if (!chatState[itemId]) {
      try {
        const messages = await apiService.getChatMessages(itemId, token);
        console.log('📨 Chat messages loaded:', messages);
        setChatMessages(prev => ({
          ...prev,
          [itemId]: messages
        }));
      } catch (error) {
        console.error('❌ Error loading chat messages:', error);
      }
    }
  };


    // Add this component BEFORE the UserDashboard component
  const TermsViewModal = ({ isOpen, onClose }) => {
    const [termsContent, setTermsContent] = useState('');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
      if (isOpen) {
        loadTermsContent();
      }
    }, [isOpen]);

    const loadTermsContent = async () => {
      try {
        const response = await fetch(`${API_BASE}/terms-content`);
        const data = await response.json();
        setTermsContent(data.content);
      } catch (error) {
        console.error('Error loading terms:', error);
        setTermsContent('Failed to load terms and conditions.');
      } finally {
        setLoading(false);
      }
    };

    if (!isOpen) return null;

    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
        <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
          <div className="p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-2xl font-bold text-gray-900">Rules & Regulations</h2>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-600 transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="border-b border-gray-200 mb-4"></div>

            {loading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600"></div>
              </div>
            ) : (
              <div className="prose prose-lg max-w-none">
                <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
                  {termsContent}
                </div>
              </div>
            )}

            <div className="flex justify-end mt-6 pt-4 border-t border-gray-200">
              <button
                onClick={onClose}
                className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Add this function with your other handlers:
const handleGetAIRecommendations = async () => {
  setAiLoading(true);
  setAiError('');
  
  try {
    console.log('🤖 Getting AI recommendations...');
    const response = await fetch(`${API_BASE}/get-ai-recommendations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({})
    });
    
    const data = await response.json();
    console.log('🤖 AI response:', data);
    
    if (data.success) {
      setAiRecommendations(data.recommendations);
      showSuccess('AI recommendations loaded! 🌱');
    } else {
      setAiError(data.error || 'Failed to get recommendations');
    }
  } catch (error) {
    console.error('🤖 AI error:', error);
    setAiError('Failed to connect to AI service');
  } finally {
    setAiLoading(false);
  }
};
  
  const handleLogout = () => {
    logout(); 
  };

  const handleSendMessage = async (itemId) => {
    const message = newMessages[itemId];
    if (!message?.trim()) {
      console.log('⚠️ Empty message, not sending');
      return;
    }

    try {
      console.log('📤 Sending message:', { itemId, message });
      await apiService.sendChatMessage(itemId, message, token);
      
      // Clear the message input
      setNewMessages(prev => ({
        ...prev,
        [itemId]: ''
      }));
      
      // Reload messages
      const messages = await apiService.getChatMessages(itemId, token);
      setChatMessages(prev => ({
        ...prev,
        [itemId]: messages
      }));
      
      console.log('✅ Message sent and messages reloaded');
    } catch (error) {
      console.error('❌ Error sending message:', error);
      alert('Failed to send message: ' + error.message);
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-green-800">Project GreenHouse</h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center">
                <img
                  src={user?.profile_picture || '/placeholder-avatar.png'}
                  alt="Profile"
                  className="w-8 h-8 rounded-full mr-2"
                  onError={(e) => e.target.src = '/placeholder-avatar.png'}
                />
                <span className="text-gray-700">{user?.name || 'User'}</span>
              </div>

              <button
                onClick={handleLogout}
                className="flex items-center px-3 py-2 text-gray-700 hover:text-gray-900 transition-colors"
              >
                <LogOut className="w-4 h-4 mr-1" />
                Logout
              </button>

            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Controls */}
        <div className="mb-6 space-y-4">
          {/* Tabs */}
          <div className="flex space-x-1 bg-gray-200 p-1 rounded-lg">
            <button
              onClick={() => setActiveTab('all')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'all' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              All Items ({items.length})
            </button>
            <button
              onClick={() => setActiveTab('my-items')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'my-items' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              My Items ({items.filter(item => 
                item.owner_email === user?.email || 
                item.owner_id === user?.user_id ||
                item.owner_id === user?.google_id
              ).length})
            </button>
            
            
            <button
              onClick={() => setActiveTab('claimed')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'claimed' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              My Claims ({myClaims.length})
            </button>
            <button
              onClick={() => setActiveTab('ai-recommendations')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'ai-recommendations' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              AI Recommendations
            </button>
          </div>

          {/* Search and Filters */}
          {activeTab !== 'ai-recommendations' && ( // ✅ START HERE
            <div className="flex flex-col sm:flex-row gap-4">
              {/* All your existing search/filter content stays the same */}
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                <input
                  type="text"
                  placeholder="Search items..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
              />
            </div>
            
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
            >
              <option value="">All Categories</option>
              {categories.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
            
           
            <button
              onClick={() => setShowTermsModal(true)}
              className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              Rules & Regulations
            </button>

            <button
              onClick={() => setShowModal(true)}
              className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <Plus className="w-4 h-4 mr-1" />
              Add Item
              </button>
            </div>
          )}
        </div>

        {/* Items Grid */}
        {activeTab !== 'ai-recommendations' && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredItems.map(item => (
                <ItemCard
                  key={item.item_id}
                  item={item}
                  currentUser={user}
                  onClaim={handleClaimItem}
                  onEdit={setEditingItem}
                  onDelete={handleDeleteItem}
                  onChatToggle={handleChatToggle}
                  showChat={chatState[item.item_id]}
                  chatMessages={chatMessages[item.item_id] || []}
                  onSendMessage={() => handleSendMessage(item.item_id)}
                  newMessage={newMessages[item.item_id] || ''}
                  setNewMessage={(message) => setNewMessages(prev => ({
                    ...prev,
                    [item.item_id]: message
                  }))}
                />
              ))}
            </div>

            {filteredItems.length === 0 && (
              <div className="text-center py-12">
                <p className="text-gray-500 text-lg">
                  {loading ? 'Loading items...' : 'No items found'}
                </p>
                {activeTab === 'all' && !loading && (
                  <p className="text-gray-400 mt-2">Be the first to add an item to the community!</p>
                )}
              </div>
            )}
          </>
        )}

 {/* 🤖 ADD THE AI CONTENT RIGHT HERE - AFTER THE ITEMS GRID */}
 {activeTab === 'ai-recommendations' && (
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-2xl font-bold text-green-800 mb-4">
                AI Recommendations
              </h2>
              <p className="text-gray-600 mb-6">
                Get creative suggestions on how to reuse recyclable materials from your PUP community!
              </p>
              
              <button
                onClick={handleGetAIRecommendations}
                disabled={aiLoading}
                className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {aiLoading ? (
                  <span className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Getting Suggestions...
                  </span>
                ) : (
                  '🌱 Get Smart Suggestions'
                )}
              </button>
            </div>

            {/* AI Response */}
            {aiRecommendations && (
              <div className="bg-white rounded-lg shadow-md p-6">
                <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
                  {aiRecommendations}
                </div>
              </div>
            )}

            {/* Error Display */}
            {aiError && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4">
                <div className="flex items-center">
                  <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                  {aiError}
                </div>
              </div>
            )}

            {/* No recommendations yet */}
            {!aiRecommendations && !aiLoading && !aiError && (
              <div className="text-center py-12">
                <div className="text-6xl mb-4">🤖</div>
                <p className="text-gray-500 text-lg">
                  Click the button above to get personalized recycling suggestions!
                </p>
                <p className="text-gray-400 text-sm mt-2">
                  Our AI will analyze available materials and give you creative Filipino ideas!
                </p>
              </div>
            )}
          </div>
        )}

      </div>

        {/* Add/Edit Modal */}
        <ItemModal
          isOpen={showModal || !!editingItem}
          onClose={() => {
            setShowModal(false);
            setEditingItem(null);
          }}
          item={editingItem}
          onSave={editingItem ? handleEditItem : handleAddItem}
          locations={locations}
          categories={categories}
          />
        
        <TermsViewModal
        isOpen={showTermsModal}
        onClose={() => setShowTermsModal(false)}
      />
      
    </div>
  );
};


// Admin Dashboard Component

// Admin Dashboard Component - COMPLETE FIXED VERSION
const AdminDashboard = () => {
  const { user, token, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('pending');
  const [pendingItems, setPendingItems] = useState([]);
  const [users, setUsers] = useState([]);
  const [locations, setLocations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showLocationModal, setShowLocationModal] = useState(false);
  const [newLocation, setNewLocation] = useState({ name: '', description: '' });
  const [currentTerms, setCurrentTerms] = useState('');
  const [editingTerms, setEditingTerms] = useState('');
  const [savingTerms, setSavingTerms] = useState(false);
  const [approvedItems, setApprovedItems] = useState([]);
  const [rejectedItems, setRejectedItems] = useState([]);
  const { showSuccess, showError, showConfirm, showPrompt } = useNotification(); 
  const [showProfileModal, setShowProfileModal] = useState(false); 

  // FIXED: Enhanced loadData with better error handling
  const loadData = React.useCallback(async () => {
    setLoading(true);
    try {
      // ALWAYS load everything, regardless of active tab
      const [pending, users, locations, approved, rejected] = await Promise.all([
        apiService.getPendingItems(token),
        apiService.getUsers(token), 
        apiService.getLocations(),
        apiService.getApprovedItems(token),
        apiService.getRejectedItems(token)
      ]);
      
      setPendingItems(pending || []);
      setUsers(users || []);
      setLocations(locations || []);
      setApprovedItems(approved || []);
      setRejectedItems(rejected || []);
      
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  }, [token]); // Remove activeTab dependency
  useEffect(() => {
    if (token && user) {
      loadData();
    }
  }, [loadData, token, user]);

  // FIXED: Enhanced item approval with error handling
  const handleApproveItem = async (itemId) => {
    try {
      console.log('✅ Approving item:', itemId);
      await apiService.approveItem(itemId, token);
      console.log('✅ Item approved successfully');
      
      // Remove from pending list immediately for better UX
      setPendingItems(prev => prev.filter(item => item.item_id !== itemId));
      
      // Also reload data to be sure
      await loadData();
    } catch (error) {
      console.error('❌ Error approving item:', error);
      alert('Failed to approve item: ' + error.message);
    }
  };

  // FIXED: Enhanced item rejection with error handling
  const handleRejectItem = async (itemId) => {
    const reason = await showPrompt('Reject Item', 'Enter rejection reason:', 'Please provide a reason...');
    if (!reason || !reason.trim()) {
      return;
    }
    
    try {
      await apiService.rejectItem(itemId, reason.trim(), token);
      showSuccess('Item rejected successfully');
      await loadData();
    } catch (error) {
      showError('Failed to reject item: ' + error.message);
    }
  };

  // FIXED: Enhanced user status toggle with error handling
  const handleToggleUserStatus = async (googleId, currentStatus) => {
    const newStatus = !currentStatus;
    const action = newStatus ? 'activate' : 'suspend';
    
    if (!window.confirm(`Are you sure you want to ${action} this user?`)) {
      return;
    }

    try {
      console.log(`🔄 ${action} user:`, googleId, 'New status:', newStatus);
      await apiService.updateUserStatus(googleId, newStatus, token);
      console.log(`✅ User ${action}d successfully`);
      
      // Update the user in the list immediately for better UX
      setUsers(prev => prev.map(user => 
        user.google_id === googleId 
          ? { ...user, is_active: newStatus }
          : user
      ));
      
      // Also reload data to be sure
      await loadData();
    } catch (error) {
      console.error(`❌ Error ${action}ing user:`, error);
      alert(`Failed to ${action} user: ` + error.message);
    }
  };

// Add delete user function with safety checks
const handleDeleteUser = async (googleId, userName) => {
  const confirmed = await showConfirm(
    '⚠️ Delete User', 
    `This will permanently delete "${userName}" and ALL their items! This cannot be undone.`
  );
  
  if (!confirmed) return;
  
  const confirmText = await showPrompt(
    'Final Confirmation', 
    `Type exactly: DELETE ${userName}`, 
    'DELETE confirmation...'
  );
  
  if (confirmText !== `DELETE ${userName}`) {
    showError('Deletion cancelled - confirmation text did not match.');
    return;
  }
  
  try {
    await apiService.deleteUser(googleId, token);
    showSuccess(`User "${userName}" deleted successfully`);
    await loadData();
  } catch (error) {
    showError('Failed to delete user: ' + error.message);
  }
};
  

  // FIXED: Enhanced location creation with validation
  const handleAddLocation = async (e) => {
    e.preventDefault();
    
    // Validate input
    if (!newLocation.name || !newLocation.name.trim()) {
      alert('Please enter a location name');
      return;
    }

    try {
      console.log('📍 Adding location:', newLocation);
      const result = await apiService.createLocation({
        name: newLocation.name.trim(),
        description: newLocation.description.trim()
      }, token);
      
      console.log('✅ Location added:', result);
      
      // Reset form and close modal
      setShowLocationModal(false);
      setNewLocation({ name: '', description: '' });
      
      // Add to locations list immediately for better UX
      if (result.location_id) {
        setLocations(prev => [...prev, {
          location_id: result.location_id,
          name: newLocation.name.trim(),
          description: newLocation.description.trim()
        }]);
      }
      
      // Also reload data to be sure
      await loadData();
    } catch (error) {
      console.error('❌ Error adding location:', error);
      alert('Failed to add location: ' + error.message);
    }
  };
  const handleDeleteLocation = async (locationId, locationName) => {
    if (!window.confirm(`Are you sure you want to delete "${locationName}"? This action cannot be undone.`)) {
      return;
    }
  
    try {
      console.log('🗑️ Deleting location:', locationId);
      await apiService.deleteLocation(locationId, token);
      console.log('✅ Location deleted successfully');
      
      // Remove from list immediately for better UX
      setLocations(prev => prev.filter(loc => loc.location_id !== locationId));
      
      // Also reload data to be sure
      await loadData();
    } catch (error) {
      console.error('❌ Error deleting location:', error);
      alert('Failed to delete location: ' + error.message);
    }
  };
  const handleLogout = () => {
    logout(); // ✅ Just call logout - your custom modal will handle confirmation
  };

   
  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading admin data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <Shield className="w-8 h-8 text-green-600 mr-2" />
              <h1 className="text-2xl font-bold text-green-800">Admin Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center">
                <User className="w-6 h-6 text-gray-600 mr-2" />
                <span className="text-gray-700">{user?.name || 'Admin'}</span>
              </div>
              <button
                onClick={() => setShowProfileModal(true)}
                className="flex items-center px-3 py-2 text-gray-700 hover:text-gray-900 transition-colors"
                title="Profile Settings"
              >
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                Settings
              </button>
              <button
                onClick={handleLogout}
                className="flex items-center px-3 py-2 text-gray-700 hover:text-gray-900"
              >
                <LogOut className="w-4 h-4 mr-1" />
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Tabs */}
        <div className="mb-6">
          <div className="flex space-x-1 bg-gray-200 p-1 rounded-lg">
            <button
              onClick={() => setActiveTab('pending')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'pending' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Pending Items ({pendingItems.length})
            </button>
            <button
              onClick={() => setActiveTab('approved')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'approved' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Approved ({approvedItems.length})
            </button>
            
            <button
              onClick={() => setActiveTab('rejected')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'rejected' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Rejected ({rejectedItems.length})
            </button>
            <button
              onClick={() => setActiveTab('users')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'users' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Users ({users.length})
            </button>
            <button
              onClick={() => setActiveTab('locations')}
              className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
                activeTab === 'locations' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Locations ({locations.length})
            </button>
            
            <button
            onClick={() => setActiveTab('terms')}
            className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
              activeTab === 'terms' ? 'bg-white text-green-700 shadow-sm' : 'text-gray-600 hover:text-gray-800'
            }`}
          >
            Terms & Conditions
          </button>
          </div>
        </div>

        {/* Content */}
        {activeTab === 'pending' && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800">Items Pending Approval</h2>
            {pendingItems.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-gray-500">No pending items</p>
                <p className="text-gray-400 text-sm mt-1">All items have been reviewed</p>
              </div>
            ) : (
             
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {pendingItems.map(item => (
                <div key={item.item_id || item.name} className="bg-white rounded-lg shadow-md overflow-hidden">
                  {/* Handle different image field names */}
                  {(item.images || item.image_urls) && (item.images || item.image_urls).length > 0 && (
                    <img 
                      src={(item.images || item.image_urls)[0]} 
                      alt={item.name} 
                      className="w-full h-400 object-cover"
                      onError={(e) => e.target.style.display = 'none'}
                    />
                  )}
                  <div className="p-4">
                    <h3 className="text-lg font-semibold mb-2">{item.name}</h3>
                    <p className="text-gray-600 mb-2">Quantity: {item.quantity}</p>
                    <p className="text-gray-600 mb-2">Category: {item.category}</p>
                    <p className="text-gray-600 mb-2">Location: {item.location}</p>
                    <p className="text-gray-600 mb-2">Owner: {item.owner_email || item.owner_name || 'Unknown'}</p>
                    {item.comments && (
                      <p className="text-gray-600 mb-4 text-sm italic">"{item.comments}"</p>
                    )}
                    
                      
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleApproveItem(item.item_id)} // ✅ Use item.item_id (the real UUID)
                        className="flex items-center px-3 py-1 bg-green-100 text-green-700 rounded-lg hover:bg-green-200 transition-colors"
                      >
                        <Check className="w-4 h-4 mr-1" />
                        Approve
                      </button>
                      <button
                        onClick={() => handleRejectItem(item.item_id)} // ✅ Use item.item_id (the real UUID)
                        className="flex items-center px-3 py-1 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 transition-colors"
                      >
                        <X className="w-4 h-4 mr-1" />
                        Reject
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            )}
          </div>
        )}


{activeTab === 'approved' && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800">Approved Items</h2>
            {approvedItems.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-gray-500">No approved items</p>
                <p className="text-gray-400 text-sm mt-1">Approved items will appear here</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {approvedItems.map(item => (
                  <div key={item.item_id || item.name} className="bg-white rounded-lg shadow-md overflow-hidden">
                    {(item.images || item.image_urls) && (item.images || item.image_urls).length > 0 && (
                      <img 
                        src={(item.images || item.image_urls)[0]} 
                        alt={item.name} 
                        className="w-full h-400 object-cover"
                        onError={(e) => e.target.style.display = 'none'}
                      />
                    )}
                    <div className="p-4">
                      <h3 className="text-lg font-semibold mb-2">{item.name}</h3>
                      <p className="text-gray-600 mb-2">Quantity: {item.quantity}</p>
                      <p className="text-gray-600 mb-2">Category: {item.category}</p>
                      <p className="text-gray-600 mb-2">Location: {item.location}</p>
                      <p className="text-gray-600 mb-2">Owner: {item.owner_email || item.owner_name || 'Unknown'}</p>
                      <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                        ✅ Approved
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'rejected' && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800">Rejected Items</h2>
            {rejectedItems.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-gray-500">No rejected items</p>
                <p className="text-gray-400 text-sm mt-1">Rejected items will appear here</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {rejectedItems.map(item => (
                  <div key={item.item_id || item.name} className="bg-white rounded-lg shadow-md overflow-hidden">
                    {(item.images || item.image_urls) && (item.images || item.image_urls).length > 0 && (
                      <img 
                        src={(item.images || item.image_urls)[0]} 
                        alt={item.name} 
                        className="w-full h-400 object-cover"
                        onError={(e) => e.target.style.display = 'none'}
                      />
                    )}
                    <div className="p-4">
                      <h3 className="text-lg font-semibold mb-2">{item.name}</h3>
                      <p className="text-gray-600 mb-2">Quantity: {item.quantity}</p>
                      <p className="text-gray-600 mb-2">Category: {item.category}</p>
                      <p className="text-gray-600 mb-2">Location: {item.location}</p>
                      <p className="text-gray-600 mb-2">Owner: {item.owner_email || item.owner_name || 'Unknown'}</p>
                      {item.rejection_reason && (
                        <p className="text-red-600 mb-2 text-sm">Reason: {item.rejection_reason}</p>
                      )}
                      <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">
                        ❌ Rejected
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'users' && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800">User Management</h2>
            {users.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-gray-500">No users found</p>
                <p className="text-gray-400 text-sm mt-1">Users will appear here once they sign up</p>
              </div>
            ) : (
              <div className="bg-white rounded-lg shadow overflow-hidden">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Login</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {users.map(userData => (
                      <tr key={userData.google_id || userData.user_id}>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <img 
                              className="h-10 w-10 rounded-full" 
                              src={userData.profile_picture || '/placeholder-avatar.png'} 
                              alt="" 
                              onError={(e) => e.target.src = '/placeholder-avatar.png'}
                            />
                            <div className="ml-4">
                              <div className="text-sm font-medium text-gray-900">{userData.name}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{userData.email}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            userData.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}>
                            {userData.is_active ? 'Active' : 'Suspended'}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {userData.last_login ? new Date(userData.last_login).toLocaleString() : 'Never'}
                        </td>

                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <div className="flex space-x-3">
                            <button
                              onClick={() => handleToggleUserStatus(userData.google_id || userData.user_id, userData.is_active)}
                              className={`text-indigo-600 hover:text-indigo-900 transition-colors ${
                                userData.is_active ? 'text-red-600 hover:text-red-900' : 'text-green-600 hover:text-green-900'
                              }`}
                            >
                              {userData.is_active ? 'Suspend' : 'Activate'}
                            </button>
                            
                            <button
                              onClick={() => handleDeleteUser(userData.google_id || userData.user_id, userData.name)}
                              className="text-red-800 hover:text-red-900 transition-colors font-bold"
                              title="⚠️ Permanently delete user and all their items"
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'locations' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold text-gray-800">Campus Locations</h2>
              <button
                onClick={() => setShowLocationModal(true)}
                className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
              >
                <Plus className="w-4 h-4 mr-1" />
                Add Location
              </button>
            </div>
            
            {locations.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-gray-500">No locations added</p>
                <p className="text-gray-400 text-sm mt-1">Add campus locations for item pickup/dropoff</p>
              </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {locations.map(location => (
                    <div key={location.location_id || location.name} className="bg-white p-4 rounded-lg shadow">
                      <div className="flex justify-between items-start mb-2">
                        <h3 className="font-semibold text-gray-800">{location.name}</h3>
                        <button
                          onClick={() => handleDeleteLocation(location.location_id, location.name)}
                          className="text-red-500 hover:text-red-700 p-1 rounded hover:bg-red-50 transition-colors"
                          title="Delete location"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                      {location.description && (
                        <p className="text-gray-600 text-sm">{location.description}</p>
                      )}
                    </div>
                  ))}
                </div>
            )}
          </div>
        )}




        {activeTab === 'terms' && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800">Terms & Conditions Management</h2>
            <p className="text-gray-600">Customize the terms and conditions that new users must accept.</p>
            
            <div className="bg-white rounded-lg shadow p-6">
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Terms & Conditions Content
                </label>
                <textarea
                  value={editingTerms}
                  onChange={(e) => setEditingTerms(e.target.value)}
                  className="w-full h-64 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500 font-mono text-sm"
                  placeholder="Enter your terms and conditions..."
                />
              </div>
              
              <div className="flex justify-between items-center">
                <button
                  onClick={async () => {
                    try {
                      const result = await apiService.getTermsContent();
                      setCurrentTerms(result.content);
                      setEditingTerms(result.content);
                    } catch (error) {
                      alert('Failed to load current terms');
                    }
                  }}
                  className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors"
                >
                  Load Current Terms
                </button>
                
                <button
                  onClick={async () => {
                    if (!editingTerms.trim()) {
                      alert('Please enter terms content');
                      return;
                    }
                    
                    setSavingTerms(true);
                    try {
                      await apiService.updateTermsContent(editingTerms, token);
                      setCurrentTerms(editingTerms);
                      alert('Terms updated successfully! New users will see the updated terms.');
                    } catch (error) {
                      alert('Failed to update terms: ' + error.message);
                    } finally {
                      setSavingTerms(false);
                    }
                  }}
                  disabled={savingTerms}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50"
                >
                  {savingTerms ? 'Saving...' : 'Update Terms'}
                </button>
              </div>
            </div>
          </div>
        )}


      </div>

      {/* Add Location Modal */}
      {showLocationModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg max-w-md w-full mx-4">
            <h3 className="text-lg font-bold mb-4">Add New Location</h3>
            <form onSubmit={handleAddLocation}>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Location Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={newLocation.name}
                  onChange={(e) => setNewLocation({...newLocation, name: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
                  required
                  placeholder="e.g., Main Building Lobby"
                />
              </div>
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">Description (Optional)</label>
                <textarea
                  value={newLocation.description}
                  onChange={(e) => setNewLocation({...newLocation, description: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
                  rows="3"
                  placeholder="Additional details about the location..."
                />
              </div>
              <div className="flex space-x-3">
                <button
                  type="submit"
                  className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors"
                >
                  Add Location
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowLocationModal(false);
                    setNewLocation({ name: '', description: '' });
                  }}
                  className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

        {showProfileModal && (
                <AdminProfile 
                  onClose={() => setShowProfileModal(false)} 
                />
              )}

      
    </div>
  );
};


const App = () => {
  const { user, isAdmin, token } = useAuth();
  
  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={
          user ? <Navigate to={isAdmin ? "/admin-portal" : "/dashboard"} replace /> : <UserLogin />
        } />
        
        {/* SECRET Admin Route */}
        <Route path="/admin-portal-xyz123" element={
          user && isAdmin ? <Navigate to="/admin-portal" replace /> : <AdminLogin />
        } />

        {/* ✅ ADD THESE TWO NEW ROUTES */}
        <Route path="/admin-forgot-password" element={<AdminForgotPassword />} />
        <Route path="/admin-reset-password" element={<AdminResetPassword />} />

        {/* Protected User Routes */}
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <UserDashboard />
          </ProtectedRoute>
        } />
        
        <Route path="/" element={
          <Navigate to={user ? (isAdmin ? "/admin-portal" : "/dashboard") : "/login"} replace />
        } />

        {/* Protected Admin Routes */}
        <Route path="/admin-portal" element={
          <ProtectedRoute adminOnly={true}>
            <AdminDashboard />
          </ProtectedRoute>
        } />

        {/* 404 - Redirect unknown routes */}
        <Route path="*" element={
          <Navigate to={user ? (isAdmin ? "/admin-portal" : "/dashboard") : "/login"} replace />
        } />
      </Routes>
    </Router>
  );
};


const EcoPantryApp = () => {
  return (
    <AuthProvider>
      <NotificationProvider>
        <App />
      </NotificationProvider>
    </AuthProvider>
  );
};

export default EcoPantryApp; 