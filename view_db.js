const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const dbFile = path.join(__dirname, 'quiz.db');
const db = new DatabaseSync(dbFile);

console.log('\n===============================================================');
console.log('   📊 SQLITE DATABASE VIEWER: quiz.db');
console.log(`   📁 File: ${dbFile}`);
console.log('===============================================================\n');

// 1. Users Table
console.log('1. TABLE: users (Registered Candidates)');
const users = db.prepare(`
  SELECT 
    id, 
    name, 
    email, 
    substr(password_hash, 1, 14) || '...' as [password_hash (scrypt)], 
    substr(salt, 1, 8) || '...' as [salt],
    created_at 
  FROM users 
  ORDER BY id ASC
`).all();
if (users.length === 0) {
  console.log('   (No users registered yet)\n');
} else {
  console.table(users);
}

// 2. Quiz Attempts Table
console.log('\n2. TABLE: quiz_attempts (Assessment Sessions & Scores)');
const attempts = db.prepare(`
  SELECT 
    a.id, 
    u.name as candidate, 
    a.status, 
    a.score || '/' || a.total_questions as [score], 
    a.percentage || '%' as [accuracy], 
    a.time_taken_seconds || 's' as [duration],
    a.started_at,
    a.completed_at
  FROM quiz_attempts a
  JOIN users u ON a.user_id = u.id
  ORDER BY a.id ASC
`).all();
if (attempts.length === 0) {
  console.log('   (No quiz attempts recorded yet)\n');
} else {
  console.table(attempts);
}

// 3. Quiz Responses Table
console.log('\n3. TABLE: quiz_responses (Latest Question Answers Stored)');
const responses = db.prepare(`
  SELECT 
    r.id, 
    r.attempt_id,
    u.name as candidate,
    'Q#' || r.question_id as question,
    r.topic,
    'Opt ' || r.user_answer as candidate_ans,
    'Opt ' || r.correct_answer as correct_ans,
    CASE WHEN r.is_correct = 1 THEN '✓ Correct' ELSE '✗ Incorrect' END as result,
    r.answered_at
  FROM quiz_responses r
  JOIN users u ON r.user_id = u.id
  ORDER BY r.id DESC
  LIMIT 15
`).all();
if (responses.length === 0) {
  console.log('   (No responses saved yet)\n');
} else {
  console.table(responses);
}

// 4. Summary Totals
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
const attemptCount = db.prepare('SELECT COUNT(*) as c FROM quiz_attempts').get().c;
const responseCount = db.prepare('SELECT COUNT(*) as c FROM quiz_responses').get().c;

console.log('---------------------------------------------------------------');
console.log(` SUMMARY TOTALS: ${userCount} Users | ${attemptCount} Attempts | ${responseCount} Stored Responses`);
console.log('---------------------------------------------------------------\n');
