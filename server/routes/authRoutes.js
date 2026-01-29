import express from 'express';
import { registerUser,verifyUser, loginUser,verifyOtp} from '../controllers/authController.js';     
const router = express.Router();

// Registration route
router.post('/register', registerUser);
// Email verification route
router.get('/verify/:token', verifyUser);   
// Login route
router.post('/login', loginUser);  
// otp verification route
router.post('/verify-otp', verifyOtp);

export default router; 