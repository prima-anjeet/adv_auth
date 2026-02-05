import express from 'express';
import { registerUser,verifyUser, loginUser,verifyOtp,myProfile, refreshToken, logoutUser,} from '../controllers/authController.js';     
import isAuth from '../middlewares/isAuth.js';
const router = express.Router();

// Registration route
router.post('/register', registerUser);
// Email verification route
router.get('/verify/:token', verifyUser);   
// Login route
router.post('/login', loginUser);  
// otp verification route
router.post('/verify-otp', verifyOtp);
// profile route
router.get('/my-profile', isAuth, myProfile);
// refresh token route
router.get('/refresh-token', refreshToken);
// logout route
router.post('/logout', isAuth, logoutUser);

export default router; 