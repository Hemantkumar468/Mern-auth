import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";
import transporter from "../config/nodemailer.js";
import { EMAIL_VERIFY_TEMPLATE ,PASSWORD_RESET_TEMPLATE} from "../config/emailTemplates.js";


export const register = async (req,res) =>{
    const {name,email,password} = req.body;
    if (!name || !email || !password) {
        return res.json({
            success: false,
            message: "please provide all fields"
        })
    }
    try {
         const exitstingUser = await User.findOne({email})

         if(exitstingUser){
            return res.json({success:false,message:"user already exists"})
         }

         const hashedPassword = await bcrypt.hash(password,10);

         const newUser = await User.create({
            name,
            email,
            password:hashedPassword,
         })
        await newUser.save();

       const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: "7d" });


             res.cookie("token", token, {
                 httpOnly: true,
                 secure: process.env.NODE_ENV === "production",
                 sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
                 maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
             });
            // Send welcome email
             const mailOptions = {
                from: process.env.SENDER_EMAIL, // Sender email address
                to: email, // Recipient email address
                subject: "walcome to our application",
                text: `Hello ${name},\n\nThank you for registering with us! We're excited to have you on board.\n\nBest regards,\nYour Application Team`
             }

             await transporter.sendMail(mailOptions);

         return res.json({ success: true });

         
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login = async (req,res) =>{
    const {email,password} = req.body;
    if (!email || !password) {
        return res.json({
            success: false,
            message: "please provide all fields"
        })
    }
    try {
       const user = await User.findOne({ email });
        if (!user) {
            return res.json({success:false,message:"invalid credentials"});
        }

        const isMatch = await bcrypt.compare(password,user.password);
        if (!isMatch) {
            return res.json({success:false,message:"invalid credentials"});
        }

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:"7d"});
        res.cookie("token",token,{
            httpOnly:true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        return res.json({success:true})
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const logout = async (req,res) =>{
    try {
        res.clearCookie("token",  {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        
        });
        return res.json({ success: true, message: "Logged out successfully" });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

// this function is used to send an opt to the user for email verification

export const sendVerifyOtp = async (req, res) =>{

    try {
        const {userId} = req.body;

        const user = await User.findById(userId);

        if (user.isVerified) {
            return res.json({success: false,message: "Account is already verified"}) }

        const otp = String(Math.floor(100000 + Math.random() * 900000))
        user.verifyOtp = otp;
        user.verifyOtpExpires = Date.now() + 24 * 60 * 60 *1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Verify your email",
            // text: `Your verification code is ${otp}`,
            html:EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        };

        await transporter.sendMail(mailOptions);
        return res.json({ success: true, message: "OTP sent successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

export const verifyEmail = async (req,res) =>{
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({
            success: false,
            message: "Please provide userId and otp"
        });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({
                success: false,
                message: "Invalid OTP"
            });
        }
        if (user.verifyOtpExpires < Date.now()) {
            return res.json({
                success: false,
                message: "OTP has expired"
            });
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpires = 0;

        await user.save();

        return res.json({
            success: true,
            message: "Email verified successfully"
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
}

// check if user is isAuthenticated
export const isAuthenticated = async (req ,res) => {
       try {
        return res.json({ success: true })
         
       } catch (error) {
              return res.json({
            success: false,
            message: error.message
        });
       }
}

// This function is used to send a reset password link to the user

export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({
            success: false,
            message: "email is required"
        });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Reset your password",
            // text: `Your reset password code is ${otp}`,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        };

        await transporter.sendMail(mailOptions);
        return res.json({ success: true, message: "Reset OTP sent successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//reset password function
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({
            success: false,
            message: "Please provide email, otp and new password"
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({
                success: false,
                message: "Invalid OTP"
            });
        }
        if (user.resetExpires < Date.now()) {
            return res.json({
                success: false,
                message: "OTP has expired"
            });
        }

       const hashedPassword = await bcrypt.hash(newPassword, 10);
           user.password = hashedPassword ;
           user.resetOtp = '';
           user.resetExpires = 0 ;
           await user.save()
        return res.json({
            success: true,
            message: "Password reset successfully"
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
}