import { createTransport } from "nodemailer";

const sendMail=async (email, subject, html) => {
   const transporter = createTransport({
       host: process.env.SMTP_HOST,
       port: process.env.SMTP_PORT,
         auth: {
              user: process.env.SMTP_USER,
              pass: process.env.SMTP_PASS
            }   
    });
    await transporter.sendMail({
        from: process.env.SMTP_FROM_EMAIL,
        to: email,
        subject: subject,
        html: html
    });
}
export default sendMail;