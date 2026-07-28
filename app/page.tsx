"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type Sentence = {
  id: string;
  text: string;
  stage: number;
  nextReview: number;
  learnt?: boolean;
  dialogTitle?: string;
  createdAt: number;
};

type PublicDialog = {
  id: string;
  title: string;
  description: string;
  sentences: string[];
};

type DictionaryEntry = {
  word: string;
  phonetic?: string;
  meanings?: Array<{
    partOfSpeech: string;
    definitions: Array<{ definition: string; example?: string }>;
  }>;
};

const STORAGE_KEY = "echocurve_site_sentences";
const intervalsInDays = [0.5, 1, 2, 3, 5, 8, 14, 21, 30, 45, 60, 90];

const starterDialogs: PublicDialog[] = [
  {
    id: "daily-checkin",
    title: "Daily Check-in",
    description: "Short conversational sentences for warm-up listening.",
    sentences: [
      "How was your morning?",
      "I slept well, but I still need coffee.",
      "Do you have any plans after work?",
      "Let's meet near the station at six.",
    ],
  },
  {
    id: "small-talk",
    title: "Small Talk",
    description: "Useful phrases for casual conversations.",
    sentences: [
      "The weather changed so quickly today.",
      "I have been trying a new language app.",
      "That sounds interesting. Tell me more.",
      "I am still practicing, but I can understand more now.",
    ],
  },
  {
    id: "travel-basics",
    title: "Travel Basics",
    description: "Sentences for arrivals, transit, and asking for help.",
    sentences: [
      "Where can I buy a ticket?",
      "Could you show me this place on the map?",
      "I would like to check in, please.",
      "Is breakfast included with the room?",
    ],
  },
];

function makeSentence(text: string, dialogTitle?: string): Sentence {
  return {
    id: crypto.randomUUID(),
    text,
    stage: 0,
    nextReview: Date.now(),
    dialogTitle,
    createdAt: Date.now(),
  };
}

function formatDue(timestamp: number) {
  const diff = timestamp - Date.now();
  if (diff <= 0) return "Due now";
  const hours = Math.ceil(diff / 36e5);
  if (hours < 24) return `Due in ${hours}h`;
  return `Due in ${Math.ceil(hours / 24)}d`;
}

function speak(text: string) {
  if (!("speechSynthesis" in window)) return;
  window.speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(text);
  const voices = window.speechSynthesis.getVoices();
  const preferredVoice = voices.find((voice) =>
    /Google US English|Microsoft Zira|Samantha|Alex/i.test(voice.name),
  );
  if (preferredVoice) utterance.voice = preferredVoice;
  utterance.rate = 0.92;
  window.speechSynthesis.speak(utterance);
}

export default function Home() {
  const [sentences, setSentences] = useState<Sentence[]>([]);
  const [newSentence, setNewSentence] = useState("");
  const [word, setWord] = useState("");
  const [dictionary, setDictionary] = useState<DictionaryEntry | null>(null);
  const [dictionaryStatus, setDictionaryStatus] = useState("");
  const [activeReviewId, setActiveReviewId] = useState<string | null>(null);
  const [isRevealed, setIsRevealed] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        setSentences(JSON.parse(saved));
      } catch {
        setSentences([]);
      }
    }
  }, []);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sentences));
  }, [sentences]);

  const dueSentences = useMemo(
    () =>
      sentences
        .filter((sentence) => !sentence.learnt && sentence.nextReview <= Date.now())
        .sort((a, b) => a.nextReview - b.nextReview),
    [sentences],
  );

  const groupedSentences = useMemo(() => {
    const groups = new Map<string, Sentence[]>();
    sentences.forEach((sentence) => {
      const title = sentence.dialogTitle || "Loose Sentences";
      groups.set(title, [...(groups.get(title) || []), sentence]);
    });
    return Array.from(groups.entries());
  }, [sentences]);

  const activeReview =
    sentences.find((sentence) => sentence.id === activeReviewId) ||
    dueSentences[0] ||
    null;

  function addSentence() {
    const text = newSentence.trim();
    if (!text) return;
    setSentences((current) => [makeSentence(text), ...current]);
    setNewSentence("");
  }

  function addDialog(dialog: PublicDialog) {
    const existing = new Set(sentences.map((sentence) => sentence.text.toLowerCase()));
    const additions = dialog.sentences
      .filter((sentence) => !existing.has(sentence.toLowerCase()))
      .map((sentence) => makeSentence(sentence, dialog.title));
    setSentences((current) => [...additions, ...current]);
  }

  function startReview() {
    if (!dueSentences[0]) return;
    setActiveReviewId(dueSentences[0].id);
    setIsRevealed(false);
    speak(dueSentences[0].text);
  }

  function finishReview(remembered: boolean) {
    if (!activeReview) return;
    const nextStage = remembered ? Math.min(activeReview.stage + 1, intervalsInDays.length) : 0;
    const days = intervalsInDays[Math.max(nextStage - 1, 0)] || 120;
    const nextReview = Date.now() + days * 24 * 60 * 60 * 1000;
    setSentences((current) =>
      current.map((sentence) =>
        sentence.id === activeReview.id
          ? {
              ...sentence,
              stage: nextStage,
              nextReview,
              learnt: nextStage >= intervalsInDays.length,
            }
          : sentence,
      ),
    );
    const next = dueSentences.find((sentence) => sentence.id !== activeReview.id);
    setActiveReviewId(next?.id || null);
    setIsRevealed(false);
    if (next) speak(next.text);
  }

  function deleteSentence(id: string) {
    setSentences((current) => current.filter((sentence) => sentence.id !== id));
  }

  async function lookupWord() {
    const term = word.trim();
    if (!term) return;
    setDictionary(null);
    setDictionaryStatus("Searching...");
    try {
      const response = await fetch(
        `https://api.dictionaryapi.dev/api/v2/entries/en/${encodeURIComponent(term)}`,
      );
      if (!response.ok) throw new Error("No result");
      const data = (await response.json()) as DictionaryEntry[];
      setDictionary(data[0]);
      setDictionaryStatus("");
    } catch {
      setDictionaryStatus("No dictionary result found.");
    }
  }

  function exportData() {
    const blob = new Blob([JSON.stringify(sentences, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "echocurve-library.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  async function importData(file: File | undefined) {
    if (!file) return;
    try {
      const parsed: unknown = JSON.parse(await file.text());
      if (!Array.isArray(parsed)) throw new Error("Expected an array");
      const imported = parsed.filter(
        (value): value is Partial<Sentence> & { text: string } =>
          typeof value === "object" &&
          value !== null &&
          typeof (value as { text?: unknown }).text === "string" &&
          (value as { text: string }).text.trim().length > 0,
      );
      const existing = new Set(sentences.map((sentence) => sentence.text.toLowerCase()));
      const additions = imported
        .filter((sentence) => !existing.has(sentence.text.toLowerCase()))
        .map((sentence) => ({
          id: sentence.id || crypto.randomUUID(),
          text: sentence.text.trim(),
          stage: typeof sentence.stage === "number" ? Math.max(0, sentence.stage) : 0,
          nextReview: typeof sentence.nextReview === "number" ? sentence.nextReview : Date.now(),
          learnt: sentence.learnt === true,
          dialogTitle: sentence.dialogTitle,
          createdAt: sentence.createdAt || Date.now(),
        }));
      setSentences((current) => [...additions, ...current]);
      setDictionaryStatus("");
    } catch {
      setDictionaryStatus("That file is not a valid EchoCurve library.");
    }
  }

  return (
    <main className="shell">
      <section className="topbar" aria-label="EchoCurve overview">
        <div>
          <p className="eyebrow">Audio-first SRS</p>
          <h1>EchoCurve</h1>
          <p className="lede">
            Train your ear first, reveal the sentence second, and let the review
            curve decide what comes back next.
          </p>
        </div>
        <div className="metric-strip" aria-label="Study statistics">
          <div>
            <strong>{sentences.length}</strong>
            <span>sentences</span>
          </div>
          <div>
            <strong>{dueSentences.length}</strong>
            <span>due now</span>
          </div>
          <div>
            <strong>{sentences.filter((sentence) => sentence.learnt).length}</strong>
            <span>learned</span>
          </div>
        </div>
      </section>

      <section className="review-band" aria-label="Review session">
        <div className="review-copy">
          <p className="section-kicker">Review queue</p>
          <h2>{activeReview ? "Listen, then reveal." : "Your queue is clear."}</h2>
          <p>
            {activeReview
              ? `${formatDue(activeReview.nextReview)} from ${activeReview.dialogTitle || "your library"}.`
              : "Add a sentence or import a starter dialog to begin."}
          </p>
        </div>
        <div className="review-player">
          <button
            className="icon-button"
            type="button"
            aria-label="Play current sentence"
            onClick={() => activeReview && speak(activeReview.text)}
            disabled={!activeReview}
          >
            Play
          </button>
          <p className={isRevealed ? "sentence revealed" : "sentence masked"}>
            {activeReview ? activeReview.text : "No sentence due"}
          </p>
          <div className="button-row">
            <button type="button" onClick={startReview} disabled={!dueSentences.length}>
              Start
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => setIsRevealed((value) => !value)}
              disabled={!activeReview}
            >
              Reveal
            </button>
            <button
              type="button"
              className="danger"
              onClick={() => finishReview(false)}
              disabled={!activeReview}
            >
              Again
            </button>
            <button
              type="button"
              className="success"
              onClick={() => finishReview(true)}
              disabled={!activeReview}
            >
              Good
            </button>
          </div>
        </div>
      </section>

      <section className="workspace-grid">
        <div className="panel composer">
          <p className="section-kicker">Capture</p>
          <h2>Add listening material</h2>
          <div className="input-row">
            <textarea
              value={newSentence}
              onChange={(event) => setNewSentence(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) addSentence();
              }}
              placeholder="Paste or type a sentence..."
              rows={3}
            />
            <button type="button" onClick={addSentence}>
              Add
            </button>
          </div>
          <div className="data-actions">
            <input
              ref={fileInputRef}
              type="file"
              accept="application/json"
              onChange={(event) => importData(event.target.files?.[0])}
            />
            <button type="button" className="secondary" onClick={() => fileInputRef.current?.click()}>
              Import
            </button>
            <button type="button" className="secondary" onClick={exportData} disabled={!sentences.length}>
              Export
            </button>
          </div>
        </div>

        <div className="panel dictionary">
          <p className="section-kicker">Dictionary</p>
          <h2>Look up a word</h2>
          <div className="input-line">
            <input
              value={word}
              onChange={(event) => setWord(event.target.value)}
              onKeyDown={(event) => event.key === "Enter" && lookupWord()}
              placeholder="Search English dictionary..."
            />
            <button type="button" onClick={lookupWord}>
              Search
            </button>
          </div>
          {dictionaryStatus && <p className="muted">{dictionaryStatus}</p>}
          {dictionary && (
            <div className="dictionary-result">
              <div>
                <strong>{dictionary.word}</strong>
                <span>{dictionary.phonetic}</span>
              </div>
              {dictionary.meanings?.slice(0, 2).map((meaning) => (
                <article key={meaning.partOfSpeech}>
                  <p>{meaning.partOfSpeech}</p>
                  <ul>
                    {meaning.definitions.slice(0, 2).map((definition) => (
                      <li key={definition.definition}>{definition.definition}</li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className="dialog-band" aria-label="Starter dialogs">
        <div className="section-heading">
          <p className="section-kicker">Public library</p>
          <h2>Starter dialogs</h2>
        </div>
        <div className="dialog-grid">
          {starterDialogs.map((dialog) => (
            <article className="dialog-card" key={dialog.id}>
              <div>
                <h3>{dialog.title}</h3>
                <p>{dialog.description}</p>
              </div>
              <ol>
                {dialog.sentences.slice(0, 3).map((sentence) => (
                  <li key={sentence}>{sentence}</li>
                ))}
              </ol>
              <div className="button-row">
                <button type="button" className="secondary" onClick={() => speak(dialog.sentences.join(". "))}>
                  Preview
                </button>
                <button type="button" onClick={() => addDialog(dialog)}>
                  Add dialog
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="library" aria-label="Sentence library">
        <div className="section-heading">
          <p className="section-kicker">Library</p>
          <h2>Your sentence stack</h2>
        </div>
        {groupedSentences.length === 0 ? (
          <p className="empty-state">No sentences yet. Add one above or start with a dialog.</p>
        ) : (
          <div className="library-list">
            {groupedSentences.map(([title, items]) => (
              <article className="library-group" key={title}>
                <header>
                  <h3>{title}</h3>
                  <span>{items.length} items</span>
                </header>
                {items.map((sentence) => (
                  <div className="library-item" key={sentence.id}>
                    <button
                      className="compact"
                      type="button"
                      aria-label={`Play ${sentence.text}`}
                      onClick={() => speak(sentence.text)}
                    >
                      Play
                    </button>
                    <p>{sentence.text}</p>
                    <span>{sentence.learnt ? "Learned" : formatDue(sentence.nextReview)}</span>
                    <button
                      className="compact danger"
                      type="button"
                      aria-label={`Delete ${sentence.text}`}
                      onClick={() => deleteSentence(sentence.id)}
                    >
                      Delete
                    </button>
                  </div>
                ))}
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
