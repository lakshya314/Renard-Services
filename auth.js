/* =========================================================
   Renard Services – Client accounts (Firebase Auth + Firestore)
   ---------------------------------------------------------
   1. Paste your Firebase web app config below
      (Firebase Console → Project settings → Your apps → Web app).
   2. In Firebase Console → Authentication → Sign-in method,
      enable "Email/Password".
   3. Create a Cloud Firestore database and publish the rules
      from firestore.rules.
   4. Under Authentication → Settings → Authorized domains,
      add your website domain (e.g. renardservices.com).

   Note: pages must be opened over http(s) (your live site or a
   local server), not by double-clicking the file.
   ========================================================= */

const firebaseConfig = {
  apiKey: "AIzaSyCmlTtRupzQVC9q8MxJ0WbV1qCxHFp6UFo",
  authDomain: "website-data-fd8bd.firebaseapp.com",
  projectId: "website-data-fd8bd",
  storageBucket: "website-data-fd8bd.firebasestorage.app",
  messagingSenderId: "612173633311",
  appId: "1:612173633311:web:6a1d381c4697a19e31c22a",
  measurementId: "G-3XRG4HPPMX"
};

/* Set to true only if Firebase Storage is enabled on your project
   (needs the Blaze plan). When false, only document names are saved. */
const USE_STORAGE = false;

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth, onAuthStateChanged, createUserWithEmailAndPassword, signInWithEmailAndPassword,
  signOut, updateProfile as updateAuthProfile, sendPasswordResetEmail, setPersistence,
  browserLocalPersistence, browserSessionPersistence, EmailAuthProvider,
  reauthenticateWithCredential, updatePassword
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, updateDoc, collection, addDoc, getDocs,
  deleteDoc, query, orderBy, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

/* ---------- helpers ---------- */
export const toISO = v => (v && typeof v.toDate === 'function') ? v.toDate().toISOString() : (v || new Date().toISOString());

const MESSAGES = {
  'auth/email-already-in-use': 'An account with this email already exists. Please log in.',
  'auth/invalid-email': 'Please enter a valid email address.',
  'auth/weak-password': 'Password is too weak. Use at least 8 characters.',
  'auth/invalid-credential': 'Incorrect email or password.',
  'auth/wrong-password': 'Incorrect email or password.',
  'auth/user-not-found': 'Incorrect email or password.',
  'auth/missing-password': 'Please enter your password.',
  'auth/too-many-requests': 'Too many attempts. Please wait a few minutes and try again.',
  'auth/network-request-failed': 'Network error. Please check your internet connection.',
  'auth/user-disabled': 'This account has been disabled. Please contact Renard Services.',
  'auth/requires-recent-login': 'Please log out and log in again, then try once more.',
  'permission-denied': 'You do not have permission to do that.',
  'unavailable': 'Service is temporarily unavailable. Please try again.'
};
export function friendly(err) {
  const code = err && (err.code || '').replace(/^firestore\//, '');
  return new Error(MESSAGES[code] || (err && err.message) || 'Something went wrong. Please try again.');
}
async function wrap(fn) { try { return await fn(); } catch (e) { throw friendly(e); } }

/* Wait for Firebase to tell us who (if anyone) is signed in */
function currentUser() {
  return new Promise(resolve => {
    const stop = onAuthStateChanged(auth, u => { stop(); resolve(u); });
  });
}

async function loadProfile(u) {
  const snap = await getDoc(doc(db, 'users', u.uid));
  const data = snap.exists() ? snap.data() : {};
  return {
    uid: u.uid,
    email: u.email,
    name: data.name || u.displayName || '',
    phone: data.phone || '',
    company: data.company || '',
    city: data.city || '',
    gstin: data.gstin || '',
    createdAt: toISO(data.createdAt || u.metadata?.creationTime)
  };
}

/* ---------- public API ---------- */
export const RenardAuth = {

  /* Create account: Firebase Auth user + profile document */
  register: ({ name, phone, email, password }) => wrap(async () => {
    await setPersistence(auth, browserLocalPersistence);
    const cred = await createUserWithEmailAndPassword(auth, email.trim(), password);
    await updateAuthProfile(cred.user, { displayName: name.trim() });
    await setDoc(doc(db, 'users', cred.user.uid), {
      name: name.trim(), phone: phone.trim(), email: cred.user.email,
      company: '', city: '', gstin: '',
      createdAt: serverTimestamp()
    });
    return cred.user;
  }),

  /* Log in with email + password */
  login: (email, password, remember = true) => wrap(async () => {
    await setPersistence(auth, remember ? browserLocalPersistence : browserSessionPersistence);
    const cred = await signInWithEmailAndPassword(auth, email.trim(), password);
    return cred.user;
  }),

  logout: () => signOut(auth),

  resetPassword: email => wrap(() => sendPasswordResetEmail(auth, email.trim())),

  /* Returns the signed-in user (or null) */
  currentUser,

  /* Use on protected pages: returns the profile, or sends the visitor to the login page */
  async requireProfile(loginPage = 'login.html') {
    const u = await currentUser();
    if (!u) { location.replace(loginPage); return null; }
    return wrap(() => loadProfile(u));
  },

  updateProfile: changes => wrap(async () => {
    const u = auth.currentUser; if (!u) throw new Error('Please log in again.');
    const allowed = {};
    ['name', 'phone', 'company', 'city', 'gstin'].forEach(k => { if (k in changes) allowed[k] = changes[k]; });
    await updateDoc(doc(db, 'users', u.uid), allowed);
    if (allowed.name) await updateAuthProfile(u, { displayName: allowed.name });
    return loadProfile(u);
  }),

  changePassword: (current, next) => wrap(async () => {
    const u = auth.currentUser; if (!u) throw new Error('Please log in again.');
    try {
      await reauthenticateWithCredential(u, EmailAuthProvider.credential(u.email, current));
    } catch (e) { throw new Error('Your current password is incorrect.'); }
    await updatePassword(u, next);
  }),

  /* ----- Service requests: users/{uid}/requests ----- */
  listRequests: () => wrap(async () => {
    const u = auth.currentUser; if (!u) return [];
    const snap = await getDocs(query(collection(db, 'users', u.uid, 'requests'), orderBy('date', 'desc')));
    return snap.docs.map(d => ({ docId: d.id, ...d.data(), date: toISO(d.data().date) }));
  }),

  addRequest: ({ service, type, note }) => wrap(async () => {
    const u = auth.currentUser; if (!u) throw new Error('Please log in again.');
    const id = 'RS-' + Math.floor(100000 + Math.random() * 900000);
    await addDoc(collection(db, 'users', u.uid, 'requests'), {
      id, service, type: type || '', note: note || '',
      status: 'Submitted', date: serverTimestamp(),
      clientName: u.displayName || '', clientEmail: u.email
    });
    return id;
  }),

  cancelRequest: docId => wrap(async () => {
    const u = auth.currentUser; if (!u) throw new Error('Please log in again.');
    await updateDoc(doc(db, 'users', u.uid, 'requests', docId), { status: 'Cancelled' });
  }),

  /* ----- Documents: users/{uid}/documents ----- */
  listDocuments: () => wrap(async () => {
    const u = auth.currentUser; if (!u) return [];
    const snap = await getDocs(query(collection(db, 'users', u.uid, 'documents'), orderBy('date', 'desc')));
    return snap.docs.map(d => ({ docId: d.id, ...d.data(), date: toISO(d.data().date) }));
  }),

  addDocuments: files => wrap(async () => {
    const u = auth.currentUser; if (!u) throw new Error('Please log in again.');
    let storageApi = null;
    if (USE_STORAGE) {
      const s = await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js");
      storageApi = { s, storage: s.getStorage(app) };
    }
    for (const f of files) {
      let url = '', path = '';
      if (storageApi) {
        path = `users/${u.uid}/documents/${Date.now()}_${f.name}`;
        const r = storageApi.s.ref(storageApi.storage, path);
        await storageApi.s.uploadBytes(r, f);
        url = await storageApi.s.getDownloadURL(r);
      }
      await addDoc(collection(db, 'users', u.uid, 'documents'), {
        name: f.name, size: f.size, type: f.type || '', url, path, date: serverTimestamp()
      });
    }
  }),

  removeDocument: item => wrap(async () => {
    const u = auth.currentUser; if (!u) throw new Error('Please log in again.');
    if (USE_STORAGE && item.path) {
      const s = await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js");
      try { await s.deleteObject(s.ref(s.getStorage(app), item.path)); } catch (e) {}
    }
    await deleteDoc(doc(db, 'users', u.uid, 'documents', item.docId));
  }),

  /* ----- Invoices: users/{uid}/invoices (added by your team) ----- */
  listInvoices: () => wrap(async () => {
    const u = auth.currentUser; if (!u) return [];
    const snap = await getDocs(query(collection(db, 'users', u.uid, 'invoices'), orderBy('date', 'desc')));
    return snap.docs.map(d => ({ docId: d.id, ...d.data(), date: toISO(d.data().date) }));
  })
};

/* ---------- Admin check ---------- */
export async function isAdmin(uid) {
  try { return (await getDoc(doc(db, 'admins', uid))).exists(); } catch (e) { return false; }
}

/* ---------- Website forms (no login needed) ---------- */
const clip = (v, n) => String(v || '').trim().slice(0, n);
export const RenardForms = {
  /* Home page "Connect With Us" / quote form  →  enquiries */
  enquiry: f => wrap(() => addDoc(collection(db, 'enquiries'), {
    name: clip(f.name, 100), phone: clip(f.phone, 20), email: clip(f.email, 120),
    service: clip(f.service, 60), message: clip(f.message, 2000),
    status: 'New', page: location.pathname, date: serverTimestamp()
  })),
  /* Home page "Join Our Team" form  →  applications */
  application: f => wrap(() => addDoc(collection(db, 'applications'), {
    name: clip(f.name, 100), phone: clip(f.phone, 20), email: clip(f.email, 120),
    city: clip(f.city, 60), message: clip(f.message, 2000),
    status: 'New', date: serverTimestamp()
  }))
};

export default RenardAuth;
