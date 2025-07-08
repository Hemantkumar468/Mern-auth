import nodemailer from "nodemailer";


const transporter = nodemailer.createTransport({
    host:'smtp-relay.brevo.com',
    port: 587,
    auth:{
        user: process.env.SMTP_USER, // Your SMTP username
        pass: process.env.SMTP_PASS  // Your SMTP password
    }

})

export default transporter;