import React, { useState, useEffect, createContext, useContext } from 'react';
import { ChevronDown, Plus, Search, User, LogOut, MapPin, Clock, MessageSquare, Check, X, Edit, Trash2, Users, Settings, Eye, Shield } from 'lucide-react';

// Auth Context
const AuthContext = createContext();


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
      const userData = localStorage.getItem('user');
      if (userData) {
        setUser(JSON.parse(userData));
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
    
    // ✅ NEW: Check if user has accepted terms (only for regular users)
    if (!adminStatus) {
      const acceptedTerms = localStorage.getItem(`terms_accepted_${userData.user_id}`);
      if (!acceptedTerms) {
        // First-time user - show terms
        fetchTermsContent();
        setShowTermsModal(true);
      }
    }
  };

// Add these functions after the login function
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

const acceptTerms = () => {
  localStorage.setItem(`terms_accepted_${user.user_id}`, 'true');
  setShowTermsModal(false);
  setHasAcceptedTerms(true);
};

const declineTerms = () => {
  // Log them out if they decline
  confirmLogout();
};

  const logout = () => {
    setShowLogoutModal(true); // Show custom modal instead of browser popup
  };
  
  const confirmLogout = () => {
    setUser(null);
    setToken(null);
    setIsAdmin(false);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('isAdmin');
    setShowLogoutModal(false); // ✅ Added missing part
  };


  
  const cancelLogout = () => { // ✅ Added missing function
    setShowLogoutModal(false);
  };

  return (
    <>
        <AuthContext.Provider value={{ 
          user, token, isAdmin, login, logout, confirmLogout, cancelLogout, showLogoutModal,
          showTermsModal, setShowTermsModal
        }}>
        {children}
      </AuthContext.Provider>
      
      {showLogoutModal && ( // ✅ Moved inside return statement
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <div className="flex items-center mb-4">
              <LogOut className="w-6 h-6 text-red-500 mr-3" />
              <h3 className="text-lg font-semibold text-gray-800">Confirm Logout</h3>
            </div>
            <p className="text-gray-600 mb-6">Are you sure you want to log out? You'll need to sign in again to access your account.</p>
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
                You must accept these terms and conditions to continue using Eco Pantry.
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

// API Service
const API_BASE = 'http://localhost:8000';

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
          onError('Login failed: No access token received');
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

// Login Component
// Login Component
const Login = () => {
  const { login } = useAuth();
  const [isAdminLogin, setIsAdminLogin] = useState(false);
  const [adminCredentials, setAdminCredentials] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleGoogleLogin = async (userData, token) => {
    try {
      console.log('Google login success:', userData);
      login(userData, token, false);
    } catch (error) {
      console.error('Google login error:', error);
      setError('Google login failed: ' + error.message);
    }
  };

  const handleAdminLogin = async (e) => {
    e.preventDefault();
    setError(''); // Clear previous errors
    setLoading(true);
    
    try {
      console.log('Attempting admin login...');
      const result = await apiService.adminLogin(adminCredentials);
      console.log('Admin login result:', result);
      
      if (result.access_token) {
        const adminUser = {
          name: result.user?.name || 'Administrator',
          email: result.user?.email || 'admin@ecopantry.com',
          user_id: result.user?.user_id || 'admin-user-001',
          google_id: result.user?.user_id || 'admin-user-001'
        };
        login(adminUser, result.access_token, true);
      } else {
        setError('Invalid admin credentials');
      }
    } catch (error) {
      console.error('Admin login error:', error);
      setError('Login failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-8">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-green-800 mb-2">Project Green House</h1>
          <p className="text-gray-600">Sustainable Exchange Platform for PUP Community</p>
        </div>

        <div className="flex mb-6">
          <button
            onClick={() => setIsAdminLogin(false)}
            className={`flex-1 py-2 px-4 rounded-l-lg font-medium transition-colors ${
              !isAdminLogin ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-700'
            }`}
          >
            Student/Faculty
          </button>
          <button
            onClick={() => setIsAdminLogin(true)}
            className={`flex-1 py-2 px-4 rounded-r-lg font-medium transition-colors ${
              isAdminLogin ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-700'
            }`}
          >
            Admin
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
            {error}
          </div>
        )}

        {!isAdminLogin ? (
          <div>
            <p className="text-center text-gray-600 mb-4">Sign in with your Google account</p>
            <GoogleLoginButton 
              onSuccess={handleGoogleLogin}
              onError={setError}
            />
          </div>
        ) : (
          <form onSubmit={handleAdminLogin}>
            <div className="mb-4">
              <label className="block text-gray-700 text-sm font-bold mb-2">
                Username
              </label>
              <input
                type="text"
                value={adminCredentials.username}
                onChange={(e) => setAdminCredentials({...adminCredentials, username: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
                required
                disabled={loading}
              />
            </div>
            <div className="mb-6">
              <label className="block text-gray-700 text-sm font-bold mb-2">
                Password
              </label>
              <input
                type="password"
                value={adminCredentials.password}
                onChange={(e) => setAdminCredentials({...adminCredentials, password: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
                required
                disabled={loading}
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Logging in...' : 'Login as Admin'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

// Item Card Component
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
              className="w-full h-48 object-cover"
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
  // FIXED: Enhanced loadData with better error handling and logging
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
      console.log('➕ Adding item:', formData);
      const result = await apiService.createItem(formData, token);
      console.log('✅ Item added:', result);
      setShowModal(false);
      
      // ✅ NEW: Show custom success modal instead of alert
      setShowSuccessModal(true);
      
      await loadData();
    } catch (error) {
      console.error('❌ Error adding item:', error);
      alert('Failed to add item: ' + error.message);
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
    if (window.confirm('Are you sure you want to delete this item?')) {
      try {
        console.log('🗑️ Deleting item:', itemId);
        await apiService.deleteItem(itemId, token);
        console.log('✅ Item deleted');
        await loadData(); // Reload data
      } catch (error) {
        console.error('❌ Error deleting item:', error);
        alert('Failed to delete item: ' + error.message);
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
                onClick={logout}
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
          </div>

          {/* Search and Filters */}
          <div className="flex flex-col sm:flex-row gap-4">
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
            
            <select
              value={filterLocation}
              onChange={(e) => setFilterLocation(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500"
            >
              <option value="">All Locations</option>
              {locations.map(loc => (
                <option key={loc.location_id || loc.name} value={loc.name}>{loc.name}</option>
              ))}
            </select>
            
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <Plus className="w-4 h-4 mr-1" />
              Add Item
            </button>
          </div>
        </div>

        {/* Items Grid */}
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
        {showSuccessModal && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
              <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
                <div className="flex items-center mb-4">
                  <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mr-4">
                    <Check className="w-6 h-6 text-green-600" />
                  </div>
                  <h3 className="text-lg font-semibold text-gray-800">Item Submitted Successfully!</h3>
                </div>
                <p className="text-gray-600 mb-6">Your item is now in line for approval. You will be notified once an admin reviews and approves your submission.</p>
                <div className="flex justify-end">
                  <button
                    onClick={() => setShowSuccessModal(false)}
                    className="bg-green-600 text-white py-2 px-6 rounded-lg hover:bg-green-700 transition-colors"
                  >
                    Got it, thanks!
                  </button>
                </div>
              </div>
            </div>
          )}
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

  // FIXED: Enhanced loadData with better error handling
  const loadData = React.useCallback(async () => {
    console.log('🔄 Admin loading data for tab:', activeTab);
    setLoading(true);
    
    try {
      // ✅ ALWAYS load counts for ALL tabs
      const [usersDataPromise, approvedDataPromise, rejectedDataPromise] = [
        apiService.getUsers(token),
        apiService.getApprovedItems(token),
        apiService.getRejectedItems(token)
      ];
      
      if (activeTab === 'pending') {
        console.log('📋 Loading pending items...');
        const [items, usersData, locationsData, approvedData, rejectedData] = await Promise.all([
          apiService.getPendingItems(token),
          usersDataPromise,
          apiService.getLocations(),
          approvedDataPromise,
          rejectedDataPromise
        ]);
        setPendingItems(Array.isArray(items) ? items : []);
        setUsers(Array.isArray(usersData) ? usersData : []);
        setLocations(Array.isArray(locationsData) ? locationsData : []);
        setApprovedItems(Array.isArray(approvedData) ? approvedData : []);
        setRejectedItems(Array.isArray(rejectedData) ? rejectedData : []);
        
      } else if (activeTab === 'users') {
        console.log('👥 Loading users...');
        const [usersData, approvedData, rejectedData] = await Promise.all([
          usersDataPromise,
          approvedDataPromise,
          rejectedDataPromise
        ]);
        setUsers(Array.isArray(usersData) ? usersData : []);
        setApprovedItems(Array.isArray(approvedData) ? approvedData : []);
        setRejectedItems(Array.isArray(rejectedData) ? rejectedData : []);
        
      } else if (activeTab === 'locations') {
        console.log('📍 Loading locations...');
        const [locationsData, usersData, approvedData, rejectedData] = await Promise.all([
          apiService.getLocations(),
          usersDataPromise,
          approvedDataPromise,
          rejectedDataPromise
        ]);
        setLocations(Array.isArray(locationsData) ? locationsData : []);
        setUsers(Array.isArray(usersData) ? usersData : []);
        setApprovedItems(Array.isArray(approvedData) ? approvedData : []);
        setRejectedItems(Array.isArray(rejectedData) ? rejectedData : []);
        
      } else if (activeTab === 'approved') {
        console.log('✅ Loading approved items...');
        const [approvedData, usersData, rejectedData] = await Promise.all([
          approvedDataPromise,
          usersDataPromise,
          rejectedDataPromise
        ]);
        setApprovedItems(Array.isArray(approvedData) ? approvedData : []);
        setUsers(Array.isArray(usersData) ? usersData : []);
        setRejectedItems(Array.isArray(rejectedData) ? rejectedData : []);
        
      } else if (activeTab === 'rejected') {
        console.log('❌ Loading rejected items...');
        const [rejectedData, usersData, approvedData] = await Promise.all([
          rejectedDataPromise,
          usersDataPromise,
          approvedDataPromise
        ]);
        setRejectedItems(Array.isArray(rejectedData) ? rejectedData : []);
        setUsers(Array.isArray(usersData) ? usersData : []);
        setApprovedItems(Array.isArray(approvedData) ? approvedData : []);
      }
      
      console.log('✅ Admin data loaded successfully');
      
    } catch (error) {
      console.error('❌ Error loading admin data:', error);
      // Set empty arrays on error
      if (activeTab === 'pending') setPendingItems([]);
      if (activeTab === 'users') setUsers([]);
      if (activeTab === 'locations') setLocations([]);
      if (activeTab === 'approved') setApprovedItems([]);
      if (activeTab === 'rejected') setRejectedItems([]);
      
      alert('Failed to load data: ' + error.message);
    } finally {
      setLoading(false);
    }
  }, [activeTab, token]);


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
    const reason = prompt('Enter rejection reason:');
    if (!reason || !reason.trim()) {
      console.log('⚠️ No rejection reason provided');
      return;
    }
  
    try {
      console.log('❌ Rejecting item:', itemId, 'Reason:', reason);
      await apiService.rejectItem(itemId, reason.trim(), token);
      console.log('✅ Item rejected successfully');
      
      // ✅ BETTER REMOVAL: Filter by exact match
      setPendingItems(prev => {
        const filtered = prev.filter(item => {
          const match = item.item_id === itemId;
          if (match) {
            console.log('🗑️ Removing rejected item from pending:', item.name);
          }
          return !match;
        });
        console.log('📊 Pending items before:', prev.length, 'after:', filtered.length);
        return filtered;
      });
      
      // Also reload data to be sure
      await loadData();
    } catch (error) {
      console.error('❌ Error rejecting item:', error);
      alert('Failed to reject item: ' + error.message);
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
    // First confirmation
    if (!window.confirm(`⚠️ DANGER: This will permanently delete "${userName}" and ALL their items!\n\nThis action CANNOT be undone. Are you absolutely sure?`)) {
      return;
    }

    // Second confirmation - must type exact text
    const confirmText = prompt(`To confirm deletion, type exactly: DELETE ${userName}`);
    if (confirmText !== `DELETE ${userName}`) {
      alert('Deletion cancelled - confirmation text did not match.');
      return;
    }

    try {
      console.log('🗑️ Permanently deleting user:', googleId, userName);
      
      // Remove user from UI immediately
      setUsers(prev => prev.filter(user => (user.google_id || user.user_id) !== googleId));
      
      // Try backend deletion
      try {
        const result = await apiService.deleteUser(googleId, token);
        alert(`User "${userName}" deleted with ${result.deleted_items || 0} items.`);
      } catch (error) {
        alert(`User "${userName}" removed from interface.`);
      }
      
      // ✅ FORCE RELOAD USERS FROM BACKEND
      await loadData();
      
    } catch (error) {
      console.error('❌ Error:', error);
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
                onClick={logout}
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
                      className="w-full h-48 object-cover"
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
                        className="w-full h-48 object-cover"
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
                        className="w-full h-48 object-cover"
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
    </div>
  );
};

// Main App Component
// Main App Component - ENHANCED VERSION
const App = () => {
  const { user, isAdmin, token } = useAuth();
  
  // Show loading while checking auth
  if (token && !user) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Checking authentication...</p>
        </div>
      </div>
    );
  }
  
  if (!user) {
    return <Login />;
  }
  
  return isAdmin ? <AdminDashboard /> : <UserDashboard />;
};

// Root Component  
const EcoPantryApp = () => {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
};

export default EcoPantryApp;