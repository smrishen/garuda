let quiz = [];
let current = 0;
let score = 0;

// Modal elements
const modal = document.getElementById("quiz-modal");
const openBtn = document.getElementById("open-quiz-btn");
const closeBtn = document.querySelector(".close");

// Open modal
openBtn.onclick = function () {
    modal.style.display = "block";
    if (quiz.length === 0) {
        loadQuiz();
    } else {
        resetQuiz();
        showQuestion();
    }
}

// Close modal
closeBtn.onclick = function () {
    modal.style.display = "none";
    resetQuiz();
}

// Close when clicking outside
window.onclick = function (event) {
    if (event.target == modal) {
        modal.style.display = "none";
        resetQuiz();
    }
}

async function loadQuiz() {
    const res = await fetch("http://localhost:3000/quiz");
    quiz = await res.json();
    showQuestion();
}

function resetQuiz() {
    current = 0;
    score = 0;
    // Reset the quiz box HTML if it was changed
    const quizBox = document.querySelector(".quiz-box");
    if (!quizBox.querySelector("#progress")) {
        quizBox.innerHTML = `
            <p id="progress"></p>
            <div id="progress-container">
                <div id="progress-bar"></div>
            </div>
            <p class="message" id="message"></p>
            <p>Would you trust this?</p>
            <div class="buttons">
                <button onclick="answer('Yes')">👍 Yes</button>
                <button onclick="answer('No')">👎 No</button>
            </div>
            <p id="result"></p>
            <button id="next-btn" onclick="nextQuestion()" style="display:none;">Next</button>
        `;
    }
}

function showQuestion() {
    document.getElementById("progress").innerText =
        "Question " + (current + 1) + " / " + quiz.length;

    // Update progress bar
    const progressBar = document.getElementById("progress-bar");
    const progressPercent = ((current) / quiz.length) * 100;
    progressBar.style.width = progressPercent + "%";

    document.getElementById("message").innerText =
        quiz[current].message;

    document.getElementById("result").innerHTML = "";
    document.getElementById("result").className = "";

    // Enable buttons
    document.querySelectorAll(".buttons button")[0].disabled = false;
    document.querySelectorAll(".buttons button")[1].disabled = false;
    document.getElementById("next-btn").style.display = "none";
}

function answer(user) {
    let q = quiz[current];
    let result = document.getElementById("result");

    if (user === q.correct) {
        score++;
        result.innerHTML =
            "✅ Correct! <br>" + q.explanation;
        result.className = "correct";
    } else {
        result.innerHTML =
            "❌ This is a scam! <br>" + q.explanation;
        result.className = "incorrect";
    }

    // Disable buttons after answer
    document.querySelectorAll(".buttons button")[0].disabled = true;
    document.querySelectorAll(".buttons button")[1].disabled = true;

    // Show next button
    document.getElementById("next-btn").style.display = "inline-block";
}

function nextQuestion() {
    current++;
    if (current >= quiz.length) {
        showResults();
        return;
    }
    showQuestion();
}

function showResults() {
    const percentage = Math.round((score / quiz.length) * 100);
    let message = "";
    if (percentage >= 80) {
        message = "Excellent! You're scam-savvy! 🛡️";
    } else if (percentage >= 60) {
        message = "Good job! Keep learning about scams. 📚";
    } else {
        message = "Be careful! Learn more about online safety. ⚠️";
    }

    document.querySelector(".quiz-box").innerHTML = `
        <h2>Quiz Finished</h2>
        <p>Your Score: ${score} / ${quiz.length} (${percentage}%)</p>
        <p>${message}</p>
        <button onclick="resetQuiz(); showQuestion();">Restart Quiz</button>
        <button onclick="modal.style.display='none'; resetQuiz();">Close</button>
    `;
}