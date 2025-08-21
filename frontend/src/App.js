import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { Plus, Search, User, LogOut, MapPin, Clock, MessageSquare, Check, X, Edit, Trash2, Shield, Menu, Users, Settings, Eye, EyeOff } from 'lucide-react';
// Auth Context
const AuthContext = createContext();

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
        setUser, 
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

// Replace localhost with your Render URL
const API_BASE = process.env.NODE_ENV === 'production' 
  ? 'https://pup-greenhouse.onrender.com'
  : 'http://localhost:8000';

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
  },

    // Notification API functions
    getNotifications: async (token) => {
      const response = await fetch(`${API_BASE}/notifications`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      return response.json();
    },
  
    markNotificationRead: async (notificationId, token) => {
      const response = await fetch(`${API_BASE}/notifications/${notificationId}/read`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      return response.json();
    },
  
    markAllNotificationsRead: async (token) => {
      const response = await fetch(`${API_BASE}/notifications/mark-all-read`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      return response.json();
    },
  
    getUnreadNotificationCount: async (token) => {
      const response = await fetch(`${API_BASE}/notifications/unread-count`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      return response.json();
    }

};

// Google OAuth Component
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




// User Login Component
const UserLogin = () => {
  const { login } = useAuth();
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleGoogleLogin = async (userData, token) => {
    try {
      console.log('Google login success:', userData);
      login(userData, token, false);
      navigate('/dashboard');
    } catch (error) {
      console.error('Google login error:', error);
      setError('Google login failed: ' + error.message);
    }
  };

  return (
    <div 
      className="min-h-screen bg-cover bg-center bg-no-repeat flex items-center justify-end p-4"
      style={{ backgroundImage: 'url(/GH-login-bg.jpg)' }}
    >
      {/* Glass Container - Right Side */}
      <div className="w-full max-w-md mr-4 md:mr-8 lg:mr-16">
        <div className="bg-gray-50/95 backdrop-blur-sm border border-gray-200/50 rounded-2xl shadow-2xl p-10 mt-20 mb-20">
          {/* Logo and Header */}
          <div className="text-center mb-8">
            <div className="flex justify-center mb-6">
              <img 
                src="/GH-Logo.png" 
                className="w-20 h-25" 
                alt="Project GreenHouse Logo" 
                onError={(e) => {
                  e.target.style.display = 'none';
                  e.target.nextSibling.style.display = 'flex';
                }}
              />
              {/* Fallback if logo doesn't load */}
            </div>
            
            <h1 className="text-base text-gray-800 mb-2">
              Polytechnic University of the Philippines
            </h1>
            <h2 className="text-4xl font-bold text-green-700 mb-2">
              Project GreenHouse
            </h2>
            <p className="text-gray-700 text-base mb-2">
              Sustainable Exchange Platform
            </p>
         </div>

          {/* Error Display */}
          {error && (
            <div className="mb-6 p-4 bg-red-100 border border-red-200 text-red-700 rounded-lg">
              <div className="flex items-center">
                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <span className="text-2xl">{error}</span>
              </div>
            </div>
          )}

          {/* Google Login Section */}
          <div className="space-y-6">
            <div className="text-center">
              <p className="text-gray-600 text-lg mb-4">
                Be part of sustaining our environment and build a greener PUP community
              </p>
            </div>

            <div className="flex justify-center">
              <div className="bg-white rounded-lg p-4 shadow-md border text-lg">
                <GoogleLoginButton 
                  onSuccess={handleGoogleLogin}
                  onError={setError}
                />
              </div>
            </div>

            {/* Features List */}
            <div class="text-gray-600 text-base text-center">
              <p class="mb-1">Contribute recyclable items</p>
              <p>within the PUP community</p>
            </div>
          </div>

          {/* Footer */}
          <div className="mt-10 pt-6 border-t border-gray-200 text-center">
            <p className="text-xs text-gray-500">© 2025 Project GreenHouse - PUP Sustainability Initiative</p>
          </div>
        </div>
      </div>
    </div>
  );
};


// Admin Login Component 
const AdminLogin = () => {
  const { login } = useAuth();
  const [adminCredentials, setAdminCredentials] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSetup, setShowSetup] = useState(false);
  const [checkingSetup, setCheckingSetup] = useState(true);
  const [showPassword, setShowPassword] = useState(false); // Password toggle state
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
      setShowSetup(true);
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
      <div 
        className="min-h-screen bg-cover bg-center bg-no-repeat flex items-center justify-center"
        style={{ backgroundImage: 'url(/GH-login-bg.jpg)' }}
      >
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white"></div>
      </div>
    );
  }

  if (showSetup) {
    return <AdminSetup onSetupComplete={() => setShowSetup(false)} />;
  }

  return (
    <div 
      className="min-h-screen bg-cover bg-center bg-no-repeat flex items-center justify-end p-4"
      style={{ backgroundImage: 'url(/GH-login-bg.jpg)' }}
    >
      {/* Glass Container - Right Side */}
      <div className="w-full max-w-md mr-4 md:mr-8 lg:mr-16">
        <div className="bg-gray-50/95 backdrop-blur-sm border border-gray-200/50 rounded-2xl shadow-2xl p-10 mt-2 mb-2">
          {/* Admin Header */}
          <div className="text-center mb-4">
            <div className="flex justify-center mb-3">
              <img 
                src="/GH-Logo.png" 
                className="w-20 h-20" 
                alt="Project GreenHouse Logo" 
                onError={(e) => e.target.style.display = 'none'}
              />
            </div>
            <h1 className="text-2xl font-bold text-gray-800 mb-2">Project GreenHouse</h1>
            <p className="text-gray-700">Polytechnic University of the Philippines</p>
            <div className="mt-3 px-4 py-2 bg-red-100 border border-red-200 text-red-700 text-sm font-medium rounded-full inline-block">
            Admin Portal
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <div className="mb-6 p-4 bg-red-100 border border-red-200 text-red-700 rounded-lg">
              <div className="flex items-center">
                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <span className="text-sm">{error}</span>
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
                className="w-full px-4 py-3 bg-white border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-all text-gray-900 placeholder-gray-500"
                required
                disabled={loading}
                placeholder="Enter admin email"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={adminCredentials.password}
                  onChange={(e) => setAdminCredentials({...adminCredentials, password: e.target.value})}
                  className="w-full px-4 py-3 pr-12 bg-white border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-all text-gray-900 placeholder-gray-500"
                  required
                  disabled={loading}
                  placeholder="Enter admin password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-700 transition-colors"
                  disabled={loading}
                >
                  {showPassword ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-red-600 hover:bg-red-700 text-white py-3 px-4 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed font-medium border border-red-500"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                  Signing in...
                </span>
              ) : (
                <span className="flex items-center justify-center">
                  Login
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
    </div>
  );
};

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
  const { user, token, setUser } = useAuth();
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordInput, setPasswordInput] = useState('');
  const [passwordResolve, setPasswordResolve] = useState(null);
  const [confirmModalData, setConfirmModalData] = useState({});
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

    // Check if sensitive changes require current password
    const isEmailChange = profileData.new_email && profileData.new_email !== user?.email;
    const isPasswordChange = profileData.new_password;
    
    if (isEmailChange || isPasswordChange) {
        // Show custom password confirmation modal
        const currentPassword = await showPasswordConfirmModal();
        if (!currentPassword) {
            return; // User cancelled
        }
        
        // Verify current password with backend first
        try {
            const verifyResponse = await fetch(`${API_BASE}/admin/verify-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ 
                    email: user?.email, 
                    password: currentPassword 
                })
            });
            
            const verifyResult = await verifyResponse.json();
            if (!verifyResult.success) {
                setError('Current password is incorrect');
                return;
            }
        } catch (error) {
            setError('Failed to verify current password');
            return;
        }
        
        // Email change confirmation
        if (isEmailChange) {
            const emailConfirmed = await showEmailConfirmModal(profileData.new_email);
            if (!emailConfirmed) {
                return; // User cancelled
            }
        }
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
        
        // ✅ UPDATE USER CONTEXT IMMEDIATELY
        const updatedUser = {
          ...user,
          name: profileData.new_name || user.name,
          email: profileData.new_email || user.email
        };
        setUser(updatedUser);
        
        // Also update localStorage to persist the changes
        localStorage.setItem('user', JSON.stringify(updatedUser));
        
        setTimeout(() => {
          onClose();
        }, 2000);
      }
      else {
        setError(result.error || 'Update failed');
      }
    } catch (error) {
      console.error('Profile update error:', error);
      setError('Update failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Helper functions for custom modals:
  const showPasswordConfirmModal = () => {
      return new Promise((resolve) => {
          setPasswordInput(''); // Clear previous input
          setPasswordResolve(() => resolve); // Store the resolve function
          setShowPasswordModal(true); // Show the modal
      });
  };

  // Add these helper functions:
  const handlePasswordConfirm = () => {
      if (passwordInput.trim()) {
          setShowPasswordModal(false);
          if (passwordResolve) passwordResolve(passwordInput);
          setPasswordInput('');
      }
  };

  const handlePasswordCancel = () => {
      setShowPasswordModal(false);
      if (passwordResolve) passwordResolve(null);
      setPasswordInput('');
  };

  const showEmailConfirmModal = (newEmail) => {
    return new Promise((resolve) => {
        setConfirmModalData({
            title: "⚠️ Change Email Address",
            message: `You are about to change your email to "${newEmail}"\n\nThis will affect your admin login. You'll need to use the new email to log in.`,
            confirmText: "Yes, Change Email",
            cancelText: "Cancel",
            onConfirm: () => {
                setShowConfirmModal(false);
                resolve(true);
            },
            onCancel: () => {
                setShowConfirmModal(false);
                resolve(false);
            }
        });
        setShowConfirmModal(true);
    });
  };

  return (
    <>
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

      {/* CUSTOM PASSWORD INPUT MODAL */}
      {showPasswordModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[70]">
              <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
                  <div className="mb-4">
                      <h3 className="text-lg font-semibold text-gray-900 mb-2">
                          🔐 Verify Your Identity
                      </h3>
                      <p className="text-gray-600 mb-4">
                          Please enter your current password to continue:
                      </p>
                      <input
                          type="password"
                          value={passwordInput}
                          onChange={(e) => setPasswordInput(e.target.value)}
                          onKeyPress={(e) => e.key === 'Enter' && handlePasswordConfirm()}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                          placeholder="Current password"
                          autoFocus
                      />
                  </div>
                  
                  <div className="flex gap-3 justify-end">
                      <button
                          onClick={handlePasswordCancel}
                          className="px-4 py-2 text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
                      >
                          Cancel
                      </button>
                      <button
                          onClick={handlePasswordConfirm}
                          disabled={!passwordInput.trim()}
                          className="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors disabled:opacity-50"
                      >
                          Confirm
                      </button>
                  </div>
              </div>
          </div>
      )}

      {/* CUSTOM CONFIRMATION MODAL */}
      {showConfirmModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[60]">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {confirmModalData.title}
              </h3>
              <p className="text-gray-600 whitespace-pre-line">
                {confirmModalData.message}
              </p>
            </div>
            
            <div className="flex gap-3 justify-end">
              <button
                onClick={confirmModalData.onCancel}
                className="px-4 py-2 text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
              >
                {confirmModalData.cancelText}
              </button>
              <button
                onClick={confirmModalData.onConfirm}
                className="px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 transition-colors"
              >
                {confirmModalData.confirmText}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
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
        {/* Image Carousel with Navigation */}
          <ImageCarousel 
            images={item.images || item.image_urls || []} 
            alt={item.name}
          />
      
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
        
        
        <div className="flex items-center mb-3 pb-2 border-b border-gray-100">
          <User className="w-4 h-4 text-gray-500 mr-2" />
          <span className="text-sm text-gray-600">
            Posted by: <span className="font-medium text-gray-800">{item.owner_name || 'Unknown User'}</span>
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
  const [imagePreviews, setImagePreviews] = useState([]);
  const [formData, setFormData] = useState({
    name: '',
    quantity: 1,
    category: '',
    location: '',
    expiry_date: '',
    duration_days: 7,
    comments: '',
    contact_info: '',
    images: null,
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

        // Contact info validation - OPTIONAL but must be valid if provided
    if (formData.contact_info && formData.contact_info.trim()) {
      const phoneNumber = formData.contact_info.trim();
      
      if (!phoneNumber.startsWith('09')) {
        newErrors.contact_info = 'Must start with 09';
      } else if (phoneNumber.length !== 11) {
        newErrors.contact_info = 'Must be exactly 11 digits';
      } else if (!/^\d+$/.test(phoneNumber)) {
        newErrors.contact_info = 'Numbers only';
      }
    }

    // Expiry date validation
    if (!formData.expiry_date) {
      newErrors.expiry_date = 'Expiry date is required';
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
                max="2030-12-31" // Reasonable future limit
              />
              {errors.expiry_date && <p className="text-red-500 text-xs mt-1">{errors.expiry_date}</p>}
              <p className="text-xs text-gray-500 mt-1">
                Select when this item will no longer be available
              </p>
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
            
           {/* Contact Info - OPTIONAL */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Contact Information
              </label>
              <div className="flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-900 bg-gray-200 border border-r-0 border-gray-300 rounded-l-md">
                  09
                </span>
                <input
                  type="text"
                  placeholder="171234567"
                  value={formData.contact_info.replace('09', '')} // Remove 09 if it exists
                  onChange={(e) => {
                    const value = e.target.value;
                    // Only allow numbers and limit to 9 digits (after 09)
                    if (/^\d*$/.test(value) && value.length <= 9) {
                      setFormData({...formData, contact_info: '09' + value});
                    }
                  }}
                  className={`flex-1 px-3 py-2 border rounded-r-lg focus:outline-none transition-colors ${
                    errors.contact_info ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                  }`}
                  disabled={loading}
                  maxLength={9}
                />
              </div>
              {errors.contact_info && <p className="text-red-500 text-xs mt-1">{errors.contact_info}</p>}
              <p className="text-xs text-gray-500 mt-1">
                Enter 9 more digits after 09 (total 11 digits)
              </p>
            </div>                                  

            {/* Images - REQUIRED for new items */}
            {!item && (
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Images <span className="text-red-500">*</span>
                </label>
                
                {/* File Input */}
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-green-500 transition-colors">
                  <input
                    type="file"
                    multiple
                    accept="image/jpeg,image/png,image/jpg,image/gif"
                    onChange={(e) => {
                      const files = e.target.files;
                      setFormData({...formData, images: files});
                      
                      // Create previews
                      const previews = [];
                      for (let i = 0; i < files.length; i++) {
                        const file = files[i];
                        const reader = new FileReader();
                        reader.onload = (e) => {
                          previews.push({
                            file: file,
                            url: e.target.result,
                            name: file.name,
                            size: file.size
                          });
                          if (previews.length === files.length) {
                            setImagePreviews(previews);
                          }
                        };
                        reader.readAsDataURL(file);
                      }
                    }}
                    className={`w-full px-3 py-2 border rounded-lg focus:outline-none transition-colors ${
                      errors.images ? 'border-red-500 focus:border-red-500' : 'border-gray-300 focus:border-green-500'
                    }`}
                    required
                    disabled={loading}
                    id="image-upload"
                  />
                  
                  <div className="mt-2">
                    <svg className="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                      <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                    <p className="mt-2 text-sm text-gray-600">
                      <label htmlFor="image-upload" className="cursor-pointer text-green-600 hover:text-green-500">
                        Click to upload
                      </label> or drag and drop
                    </p>
                    <p className="text-xs text-gray-500">PNG, JPG, GIF up to 5MB each</p>
                  </div>
                </div>
                
                {errors.images && <p className="text-red-500 text-xs mt-1">{errors.images}</p>}
                
                {/* Image Previews */}
                {imagePreviews.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-sm font-medium text-gray-700 mb-2">
                      Selected Images ({imagePreviews.length})
                    </h4>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                      {imagePreviews.map((preview, index) => (
                        <div key={index} className="relative group">
                          <img
                            src={preview.url}
                            alt={`Preview ${index + 1}`}
                            className="w-full h-24 object-cover rounded-lg border border-gray-200"
                          />
                          <button
                            type="button"
                            onClick={() => {
                              // Remove image from previews
                              const newPreviews = imagePreviews.filter((_, i) => i !== index);
                              setImagePreviews(newPreviews);
                              
                              // Update formData.images
                              const dt = new DataTransfer();
                              for (let i = 0; i < formData.images.length; i++) {
                                if (i !== index) {
                                  dt.items.add(formData.images[i]);
                                }
                              }
                              setFormData({...formData, images: dt.files});
                            }}
                            className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full w-6 h-6 flex items-center justify-center text-xs hover:bg-red-600 opacity-0 group-hover:opacity-100 transition-opacity"
                          >
                            ×
                          </button>
                          <div className="absolute bottom-0 left-0 right-0 bg-black bg-opacity-50 text-white text-xs p-1 rounded-b-lg truncate">
                            {preview.name}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
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

const ImageCarousel = ({ images, alt = "Item image" }) => {
  const [currentIndex, setCurrentIndex] = useState(0);
  
  if (!images || images.length === 0) {
    return (
      <div className="w-full h-48 bg-gray-200 flex items-center justify-center rounded-lg">
        <span className="text-gray-500">No images available</span>
      </div>
    );
  }

  const nextImage = () => {
    setCurrentIndex((prev) => (prev + 1) % images.length);
  };

  const prevImage = () => {
    setCurrentIndex((prev) => (prev - 1 + images.length) % images.length);
  };

  const goToImage = (index) => {
    setCurrentIndex(index);
  };

  return (
    <div className="relative">
      {/* Main Image */}
      <div className="relative w-full bg-gray-100 rounded-lg overflow-hidden">
        <img
          src={images[currentIndex]}
          alt={`${alt} ${currentIndex + 1}`}
          className="w-full object-contain"
          onError={(e) => {
            e.target.src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZGRkIi8+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNCIgZmlsbD0iIzk5OSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZHk9Ii4zZW0iPkltYWdlIE5vdCBGb3VuZDwvdGV4dD48L3N2Zz4=';
          }}
        />
        
        {/* Navigation Arrows - Only show if more than 1 image */}
        {images.length > 1 && (
          <>
            <button
              onClick={prevImage}
              className="absolute left-2 top-1/2 transform -translate-y-1/2 bg-black bg-opacity-50 text-white rounded-full w-8 h-8 flex items-center justify-center hover:bg-opacity-75 transition-all"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </button>
            <button
              onClick={nextImage}
              className="absolute right-2 top-1/2 transform -translate-y-1/2 bg-black bg-opacity-50 text-white rounded-full w-8 h-8 flex items-center justify-center hover:bg-opacity-75 transition-all"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </button>
          </>
        )}
        
        {/* Image Counter */}
        {images.length > 1 && (
          <div className="absolute top-2 right-2 bg-black bg-opacity-75 text-white text-xs px-2 py-1 rounded-full">
            {currentIndex + 1} / {images.length}
          </div>
        )}
      </div>
      
      {/* Thumbnail Navigation - Only show if more than 1 image */}
      {images.length > 1 && (
        <div className="flex gap-2 mt-3 overflow-x-auto pb-2">
          {images.map((image, index) => (
            <button
              key={index}
              onClick={() => goToImage(index)}
              className={`flex-shrink-0 w-16 h-16 rounded-lg overflow-hidden border-2 transition-all ${
                index === currentIndex 
                  ? 'border-green-500 ring-2 ring-green-200' 
                  : 'border-gray-200 hover:border-gray-300'
              }`}
            >
              <img
                src={image}
                alt={`Thumbnail ${index + 1}`}
                className="w-full object-contain"
                onError={(e) => {
                  e.target.src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgZmlsbD0iI2RkZCIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMTAiIGZpbGw9IiM5OTkiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGR5PSIuM2VtIj5OL0E8L3RleHQ+PC9zdmc+';
                }}
              />
            </button>
          ))}
        </div>
      )}
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
  
  // 📱 NEW: Sidebar state for ALL screen sizes
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

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

  const NotificationBell = ({ user, token }) => {
    const [notifications, setNotifications] = useState([]);
    const [unreadCount, setUnreadCount] = useState(0);
    const [isOpen, setIsOpen] = useState(false);
    const [loading, setLoading] = useState(false);
  
    // Load notifications and unread count
    const loadNotifications = async () => {
      try {
        const [notificationsData, unreadData] = await Promise.all([
          apiService.getNotifications(token),
          apiService.getUnreadNotificationCount(token)
        ]);
        
        setNotifications(notificationsData || []);
        setUnreadCount(unreadData?.unread_count || 0);
      } catch (error) {
        console.error('Error loading notifications:', error);
      }
    };
  
    // Load notifications on mount and periodically
    useEffect(() => {
      if (token && user) {
        loadNotifications();
        
        // Refresh every 30 seconds
        const interval = setInterval(loadNotifications, 30000);
        return () => clearInterval(interval);
      }
    }, [token, user]);
  
    // Mark notification as read
    const markAsRead = async (notificationId) => {
      try {
        await apiService.markNotificationRead(notificationId, token);
        // Update local state
        setNotifications(prev => 
          prev.map(notif => 
            notif.notification_id === notificationId 
              ? { ...notif, is_read: true }
              : notif
          )
        );
        setUnreadCount(prev => Math.max(0, prev - 1));
      } catch (error) {
        console.error('Error marking notification as read:', error);
      }
    };
  
    // Mark all as read
    const markAllAsRead = async () => {
      try {
        setLoading(true);
        await apiService.markAllNotificationsRead(token);
        setNotifications(prev => prev.map(notif => ({ ...notif, is_read: true })));
        setUnreadCount(0);
      } catch (error) {
        console.error('Error marking all as read:', error);
      } finally {
        setLoading(false);
      }
    };
  
    // Format time ago
    const timeAgo = (dateString) => {
      const now = new Date();
      const date = new Date(dateString);
      const diffInMs = now - date;
      const diffInMinutes = Math.floor(diffInMs / (1000 * 60));
      const diffInHours = Math.floor(diffInMinutes / 60);
      const diffInDays = Math.floor(diffInHours / 24);
  
      if (diffInMinutes < 1) return 'Just now';
      if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
      if (diffInHours < 24) return `${diffInHours}h ago`;
      if (diffInDays < 7) return `${diffInDays}d ago`;
      return date.toLocaleDateString();
    };
  
    // Get notification icon
    const getNotificationIcon = (type) => {
      return '🔔';
    };
    
  
    return (
      <div className="relative">
        {/* Notification Bell Button */}
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="relative p-2 text-gray-700 hover:text-gray-900 transition-colors"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          
          {/* Unread Count Badge */}
          {unreadCount > 0 && (
            <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </button>
  
        {/* Notification Dropdown */}
        {isOpen && (
          <>
            {/* Overlay */}
            <div 
              className="fixed inset-0 z-10" 
              onClick={() => setIsOpen(false)}
            />
            
            {/* Dropdown */}
            <div className="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-xl border border-gray-200 z-20">
              {/* Header */}
              <div className="p-4 border-b border-gray-200">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold text-gray-800">Notifications</h3>
                  {unreadCount > 0 && (
                    <button
                      onClick={markAllAsRead}
                      disabled={loading}
                      className="text-sm text-blue-600 hover:text-blue-800 disabled:opacity-50"
                    >
                      {loading ? 'Marking...' : 'Mark all read'}
                    </button>
                  )}
                </div>
              </div>
  
              {/* Notifications List */}
              <div className="max-h-96 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="p-8 text-center text-gray-500">
                    <svg className="w-12 h-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                    </svg>
                    <p>No notifications yet</p>
                    <p className="text-sm mt-1">We'll notify you when something happens!</p>
                  </div>
                ) : (
                  notifications.map((notification) => (
                    <div
                      key={notification.notification_id}
                      className={`p-4 border-b border-gray-100 hover:bg-gray-50 cursor-pointer transition-colors ${
                        !notification.is_read ? 'bg-blue-50 border-l-4 border-l-blue-500' : ''
                      }`}
                      onClick={() => {
                        if (!notification.is_read) {
                          markAsRead(notification.notification_id);
                        }
                        setIsOpen(false);
                        // Navigate to action_url if needed
                        if (notification.action_url) {
                          // You can add navigation logic here
                        }
                      }}
                    >
                      <div className="flex items-start space-x-3">
                        <span className="text-lg">{getNotificationIcon(notification.type)}</span>
                        <div className="flex-1 min-w-0">
                          <p className={`text-sm font-medium text-gray-900 ${!notification.is_read ? 'font-semibold' : ''}`}>
                            {notification.title}
                          </p>
                          <p className="text-sm text-gray-600 mt-1">
                            {notification.message}
                          </p>
                          <p className="text-xs text-gray-400 mt-1">
                            {timeAgo(notification.created_at)}
                          </p>
                        </div>
                        {!notification.is_read && (
                          <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
  
              {/* Footer */}
              {notifications.length > 0 && (
                <div className="p-3 border-t border-gray-200 text-center">
                  <button 
                    onClick={() => setIsOpen(false)}
                    className="text-sm text-gray-600 hover:text-gray-800"
                  >
                    Close
                  </button>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    );
  };
  
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

  // 📱 Close sidebar when tab changes (mobile UX)
  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setIsSidebarOpen(false); // Close sidebar on mobile after selection
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
    <div className="min-h-screen bg-gray-50 flex">
      {/* 📱 SIDEBAR OVERLAY - ALL SCREEN SIZES */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-40"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}

      {/* 🔧 COLLAPSIBLE SIDEBAR - ALL SCREEN SIZES */}
      <div className={`
        fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg transform transition-transform duration-300 ease-in-out
        ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        {/* Sidebar Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold text-green-800">Navigation</h2>
          {/* Close button - visible on all screen sizes */}
          <button
            onClick={() => setIsSidebarOpen(false)}
            className="p-2 text-gray-500 hover:text-gray-700"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Sidebar Navigation */}
        <nav className="p-4 space-y-2 flex-1 overflow-y-auto">
          <button
            onClick={() => handleTabChange('all')}
            className={`w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center justify-between ${
              activeTab === 'all' 
                ? 'bg-green-100 text-green-800 font-medium' 
                : 'text-gray-700 hover:bg-gray-100'
            }`}
          >
            <span className="flex items-center">
              <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              All Items
            </span>
            <span className="bg-gray-200 text-gray-600 text-xs px-2 py-1 rounded-full">
              {items.filter(item => {
                const isMyItem = item.owner_email === user?.email || 
                               item.owner_id === user?.user_id ||
                               item.owner_id === user?.google_id;
                return !isMyItem;
              }).length}
            </span>
          </button>

          <button
            onClick={() => handleTabChange('my-items')}
            className={`w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center justify-between ${
              activeTab === 'my-items' 
                ? 'bg-green-100 text-green-800 font-medium' 
                : 'text-gray-700 hover:bg-gray-100'
            }`}
          >
            <span className="flex items-center">
              <User className="w-5 h-5 mr-3" />
              My Items
            </span>
            <span className="bg-gray-200 text-gray-600 text-xs px-2 py-1 rounded-full">
              {items.filter(item => 
                item.owner_email === user?.email || 
                item.owner_id === user?.user_id ||
                item.owner_id === user?.google_id
              ).length}
            </span>
          </button>

          <button
            onClick={() => handleTabChange('claimed')}
            className={`w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center justify-between ${
              activeTab === 'claimed' 
                ? 'bg-green-100 text-green-800 font-medium' 
                : 'text-gray-700 hover:bg-gray-100'
            }`}
          >
            <span className="flex items-center">
              <Check className="w-5 h-5 mr-3" />
              My Claims
            </span>
            <span className="bg-gray-200 text-gray-600 text-xs px-2 py-1 rounded-full">
              {myClaims.length}
            </span>
          </button>

          <button
            onClick={() => handleTabChange('ai-recommendations')}
            className={`w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center justify-between ${
              activeTab === 'ai-recommendations' 
                ? 'bg-green-100 text-green-800 font-medium' 
                : 'text-gray-700 hover:bg-gray-100'
            }`}
          >
            <span className="flex items-center">
              <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
              AI Corner
            </span>
            <span className="bg-purple-100 text-purple-600 text-xs px-2 py-1 rounded-full">
              🤖
            </span>
          </button>

          {/* Rules & Regulations - RIGHT BELOW AI Corner */}
          <div className="pt-2 border-t border-gray-200">
            <button
              onClick={() => {
                setShowTermsModal(true);
                setIsSidebarOpen(false); // Close sidebar when opening modal
              }}
              className="w-full text-left px-4 py-3 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors flex items-center"
            >
              <svg className="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Rules & Regulations
            </button>
          </div>
        </nav>
      </div>

      {/* 📱 MAIN CONTENT AREA - Full Width */}
      <div className="flex-1 flex flex-col min-h-screen">
        {/* 🔧 TOP HEADER - With Hamburger for All Screen Sizes */}
        <header className="bg-white shadow-sm border-b">
          <div className="px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-4">
              <div className="flex items-center">
                {/* 📱 Hamburger Menu - All Screen Sizes */}
                <button
                  onClick={() => setIsSidebarOpen(true)}
                  className="p-2 text-gray-500 hover:text-gray-700 mr-3"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                  </svg>
                </button>
                
                <h1 className="text-xl lg:text-2xl font-bold text-green-800">Project GreenHouse</h1>
              </div>
              
                <div className="flex items-center space-x-2 lg:space-x-4">
                    {/* Notification Bell */}
                    <NotificationBell user={user} token={token} />
                  <div className="hidden sm:flex items-center">
                    <img
                      src={user?.profile_picture || '/placeholder-avatar.png'}
                      alt="Profile"
                      className="w-6 h-6 lg:w-8 lg:h-8 rounded-full mr-2"
                      onError={(e) => e.target.src = '/placeholder-avatar.png'}
                    />
                    <span className="text-gray-700 text-sm lg:text-base">{user?.name || 'User'}</span>
                  </div>

                  <button
                    onClick={handleLogout}
                    className="flex items-center px-2 lg:px-3 py-2 text-gray-700 hover:text-gray-900 transition-colors"
                  >
                    <LogOut className="w-4 h-4 mr-1" />
                    <span className="hidden sm:inline">Logout</span>
                  </button>
                </div>
            </div>
          </div>
        </header>

        {/* 🔧 MAIN CONTENT - Responsive with Centered Layout */}
        <main className="flex-1 px-4 sm:px-6 lg:px-8 xl:px-16 2xl:px-32 py-4 lg:py-8 max-w-7xl mx-auto w-full">
          {/* 📱 CONTROLS BAR - Responsive */}
          <div className="mb-4 lg:mb-6 space-y-4 max-w-6xl mx-auto">
            {/* Search and Filters - Only show when not on AI tab */}
            {activeTab !== 'ai-recommendations' && (
              <div className="flex flex-col sm:flex-row gap-2 lg:gap-4 items-stretch sm:items-center">
                {/* Search */}
                <div className="flex-[2] relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                  <input
                    type="text"
                    placeholder="Search items..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 text-sm lg:text-base border border-gray-300 rounded-lg focus:outline-none focus:border-green-500 h-11"
                  />
                </div>
                
                {/* Category Filter */}
                <div className="flex-[0.7]">
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="w-full px-3 lg:px-4 py-2.5 text-sm lg:text-base border border-gray-300 rounded-lg focus:outline-none focus:border-green-500 h-11"
                  >
                    <option value="">All Categories</option>
                    {categories.map(cat => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>

                {/* Add Item Button */}
                <div className="flex-[0.6]">
                  <button
                    onClick={() => setShowModal(true)}
                    className="w-full flex items-center justify-center px-4 lg:px-6 py-2.5 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors text-sm lg:text-base whitespace-nowrap h-11"
                  >
                    <Plus className="w-4 h-4 mr-1" />
                    <span className="hidden sm:inline">Add Item</span>
                    <span className="sm:hidden">Add</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* 📱 CONTENT AREA - Responsive Grid with Centered Layout */}
          {activeTab !== 'ai-recommendations' && (
            <div className="max-w-6xl mx-auto">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-4 lg:gap-6">
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
            </div>
          )}

          {/* 🤖 AI RECOMMENDATIONS TAB - Responsive with Centered Layout */}
          {activeTab === 'ai-recommendations' && (
            <div className="space-y-6 max-w-4xl mx-auto">
              <div className="text-center">
                <h2 className="text-xl lg:text-2xl font-bold text-green-800 mb-4">
                  AI Recommendations
                </h2>
                <p className="text-gray-600 mb-6 text-sm lg:text-base">
                  Get creative suggestions on how to reuse recyclable materials from your PUP community!
                </p>
                
                <button
                  onClick={handleGetAIRecommendations}
                  disabled={aiLoading}
                  className="px-4 lg:px-6 py-2 lg:py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-sm lg:text-base"
                >
                  {aiLoading ? (
                    <span className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-4 w-4 lg:h-5 lg:w-5 border-b-2 border-white mr-2"></div>
                      Getting Suggestions...
                    </span>
                  ) : (
                    '🌱 Get Smart Suggestions'
                  )}
                </button>
              </div>

              {/* AI Response */}
              {aiRecommendations && (
                <div className="bg-white rounded-lg shadow-md p-4 lg:p-6">
                  <div className="whitespace-pre-wrap text-gray-700 leading-relaxed text-sm lg:text-base">
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
                    <span className="text-sm lg:text-base">{aiError}</span>
                  </div>
                </div>
              )}

              {/* No recommendations yet */}
              {!aiRecommendations && !aiLoading && !aiError && (
                <div className="text-center py-12">
                  <div className="text-4xl lg:text-6xl mb-4">🤖</div>
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
        </main>
      </div>

      {/* 📱 MODALS - Responsive */}
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


//delete user function with safety checks
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
    logout(); 
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
                  <ImageCarousel 
                    images={item.images || item.image_urls || []} 
                    alt={item.name}
                  />
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

                    <ImageCarousel 
                      images={item.images || item.image_urls || []} 
                      alt={item.name}
                    />
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
                    <ImageCarousel 
                      images={item.images || item.image_urls || []} 
                      alt={item.name}
                    />
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