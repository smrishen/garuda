const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());

const quiz = [

    {
        message: "Vehicle no KA19MM0404 has been booked for violation in traffic rules. Details may be viewed at https://itmschalan.parivahan.govv.in/approved-report?id=MTECE4354.MoRTH",
        correct: "No",
        explanation: "this is a common traffic violation scam. always verify the link beforehand ,and check the patterns.ALways check official Parivahan website directly."
    },

    {
        message: "Your bank account will be suspended today. Click here to verify immediately.",
        correct: "No",
        explanation: "Banks never ask verification through random links."
    },

    {
        message: "Congratulations! You won an iPhone. Pay ₹99 shipping to receive it.",
        correct: "No",
        explanation: "Fake prize scams trick users into paying small fees."
    },

    {
        message: "Your OTP is required to complete your KYC update. Reply with the OTP.",
        correct: "No",
        explanation: "No company will ask for OTP through messages."
    },

    {
        message: "Hi mom, I lost my phone. This is my new number. Send ₹5000 urgently.",
        correct: "No",
        explanation: "This is a common impersonation scam."
    },

    {
        message: "Your electricity will be disconnected tonight. Pay bill immediately using this link.",
        correct: "No",
        explanation: "Utility companies don't threaten sudden disconnections via SMS."
    },

    {
        message: "Amazon: Your account has suspicious activity. Login here immediately.",
        correct: "No",
        explanation: "Fake login links are used to steal passwords."
    },

    {
        message: "You received a job offer abroad. Pay ₹2000 processing fee.",
        correct: "No",
        explanation: "Legitimate jobs do not ask money upfront."
    },

    {
        message: "Netflix subscription failed. Update payment details here.",
        correct: "No",
        explanation: "Always check official websites instead of SMS links."
    },

    {
        message: "Your PAN card will be blocked. Verify details in this link.",
        correct: "No",
        explanation: "Government services never request verification through random links."
    }

];

app.get("/quiz", (req, res) => {
    res.json(quiz);
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});