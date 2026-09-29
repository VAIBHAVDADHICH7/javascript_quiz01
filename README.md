# JavaScript Mastery Quiz (Professional Edition)

A full-stack, enterprise-grade assessment platform featuring **User Registration & Authentication**, **Real-Time Response Saving**, and **SQLite Database Persistence**.

---

## 🚀 Key Features

1. **Mandatory Pre-Quiz Candidate Gateway**:
   - The entire quiz, questions, code runner, and timer are **completely locked** behind an authentication gate.
   - Candidates must either **Sign In** or **Register** before accessing any part of the assessment.
   - Secure registration and login powered by **scrypt password hashing** and crypto salting.
   - Persistent candidate session tokens stored in the SQLite database and validated on page load.
   - Candidate profile chip in the top header with initials avatar and one-click Sign Out (which returns to the locked auth screen).

2. **Real-Time Database Persistence (SQLite)**:
   - **Zero Data Loss**: Every question answered or changed is immediately persisted to the `quiz.db` database via `/api/responses/save`.
   - Real-time sync indicator (`Saved to DB ✓`, `Saving to Database...`).
   - Automatically resumes active attempt and restores previously chosen answers from SQLite upon login.

3. **Candidate Performance & Competency Statistics**:
   - **"📈 My Statistics"**: Comprehensive real-time analytics modal for the candidate:
     - **Hero KPI Cards**: Global cohort rank (`#1 / N`), highest score, overall question accuracy rate (`%` and fraction correct), and pacing metrics (avg seconds per question with a speed classification badge: *Rapid*, *Moderate*, *Deliberate*).
     - **Key Strengths & Recommended Focus**: Dynamic badges highlighting domains where accuracy is $\ge 60\%$ vs. domains requiring review ($< 60\%$).
     - **Topic Mastery Breakdown**: Interactive progress bars and percentage indicators across all JavaScript topics.
     - **Difficulty Performance Matrix**: 4-quadrant breakdown analyzing accuracy across *Easy*, *Medium*, *Hard*, and *Expert* questions.

4. **Detailed Assessment History**:
   - **"📋 My History"**: Displays every past quiz attempt with date, score, accuracy percentage, and time taken.
   - **"Inspect Answers"**: Click on any past attempt to view question-by-question responses, your answer vs. the correct answer, and detailed ECMAScript explanations.

5. **Global Leaderboard**:
   - **"🏆 Leaderboard"**: Live rankings for registered candidates showing top score, accuracy, and fastest completion time with medal badges (🥇 🥈 🥉).

6. **Fortified Admin Security & Privacy Protection**:
   - **Hidden Endpoint**: Public links to `/admin` are completely removed from the candidate UI.
   - **Passkey Gate**: Access to `/admin` requires entering the secure administrator passkey configured in `.env`.
   - **Anti-Brute Force Protection**: IP rate-limiting automatically locks out any IP for 15 minutes after 5 failed attempts.
   - **Timing Attack Resistance**: Uses `crypto.timingSafeEqual` for constant-time credential comparison.
   - **Zero Data Exposure**: Raw candidate session tokens, passwords, and cryptographic salts are masked and never exposed, preventing session hijacking.
   - **Ephemeral Admin Sessions**: Admin tokens expire after 2 hours and are stored in `sessionStorage` (cleared automatically on tab close).

7. **Admin Cohort Analytics & Telemetry**:
   - **"📈 Cohort Analytics"** tab in the admin portal:
     - **Executive KPIs**: Cohort pass rate ($\ge 70\%$), completed vs. in-progress attempts, average score, score spread (min-to-max), and average duration per attempt.
     - **Score Distribution Bands**: Color-coded progress bands mapping cohort percentiles: Distinction ($90\% - 100\%$), Proficient ($70\% - 89\%$), Needs Improvement ($50\% - 69\%$), and At Risk ($< 50\%$).
     - **Cohort Topic Competency Benchmarking**: Cross-candidate accuracy benchmarking across all knowledge domains.
     - **Difficulty Level Accuracy**: Real-time pass rates across Easy, Medium, Hard, and Expert levels.
     - **Item Analysis**: Top 5 hardest questions (highest failure rate) and top 5 easiest questions (highest pass rate) to identify curriculum gaps.

---

## 🛠️ How to Run

### 1. Start the Server
In PowerShell or your terminal inside this folder:
```bash
npm start
```
*(Alternatively: `node server.js`)*

### 2. Open in Your Browser
Navigate to:
```
http://localhost:3000
```

---

## 🗄️ Database Schema (`quiz.db`)

- **`users`**: `id`, `name`, `email`, `password_hash`, `salt`, `created_at`
- **`auth_tokens`**: `token`, `user_id`, `created_at`, `expires_at`
- **`quiz_attempts`**: `id`, `user_id`, `quiz_title`, `status`, `score`, `total_questions`, `percentage`, `time_taken_seconds`, `started_at`, `completed_at`
- **`quiz_responses`**: `id`, `attempt_id`, `user_id`, `question_id`, `topic`, `difficulty`, `user_answer`, `correct_answer`, `is_correct`, `answered_at`
