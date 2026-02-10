import { Resend } from "resend";

const sendMail = async (email, subject, html) => {
  try {
    const resend = new Resend(process.env.RESEND_API_KEY);
    console.log(`Attempting to send email to ${email} via Resend...`);
    const { data, error } = await resend.emails.send({
      from: "onboarding@resend.dev",
      to: [email],
      subject: subject,
      html: html,
    });

    if (error) {
      console.error("Resend API Error:", error);
      throw new Error(error.message || "Failed to send email");
    }

    console.log(`Email sent successfully via Resend. ID: ${data?.id}`);
    return data;
  } catch (error) {
    console.error("Email sending exception:", error);
    throw error;
  }
};

export default sendMail;
