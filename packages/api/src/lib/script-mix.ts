/**
 * UTS #39 restriction levels (https://www.unicode.org/reports/tr39/#Restriction_Level_Detection)
 * for one domain label, from the Script_Extensions property of each code
 * point (JavaScript `\\p{scx=…}`, Unicode {process.versions.unicode}).
 *
 * A label is Highly Restrictive when all of its letters share one script, or
 * it is covered by Latin + Han + Hiragana + Katakana, Latin + Han + Bopomofo
 * or Latin + Han + Hangul. Anything less (Latin with Cyrillic or Greek in
 * one label, for example) is the classic disguise of a lookalike domain.
 * Common and Inherited code points (digits, hyphen, combining marks) belong
 * to every script.
 */

/** Script values of the Script_Extensions property (Common and Inherited excluded). */
export const SCRIPT_NAMES: readonly string[] = [
  'Adlam', 'Ahom', 'Anatolian_Hieroglyphs', 'Arabic', 'Armenian', 'Avestan', 'Balinese', 'Bamum',
  'Bassa_Vah', 'Batak', 'Bengali', 'Bhaiksuki', 'Bopomofo', 'Brahmi', 'Braille', 'Buginese',
  'Buhid', 'Canadian_Aboriginal', 'Carian', 'Caucasian_Albanian', 'Chakma', 'Cham', 'Cherokee',
  'Chorasmian', 'Coptic', 'Cuneiform', 'Cypriot', 'Cypro_Minoan', 'Cyrillic', 'Deseret',
  'Devanagari', 'Dives_Akuru', 'Dogra', 'Duployan', 'Egyptian_Hieroglyphs', 'Elbasan', 'Elymaic',
  'Ethiopic', 'Garay', 'Georgian', 'Glagolitic', 'Gothic', 'Grantha', 'Greek', 'Gujarati',
  'Gunjala_Gondi', 'Gurmukhi', 'Gurung_Khema', 'Han', 'Hangul', 'Hanifi_Rohingya', 'Hanunoo',
  'Hatran', 'Hebrew', 'Hiragana', 'Imperial_Aramaic', 'Inscriptional_Pahlavi',
  'Inscriptional_Parthian', 'Javanese', 'Kaithi', 'Kannada', 'Katakana', 'Kawi', 'Kayah_Li',
  'Kharoshthi', 'Khitan_Small_Script', 'Khmer', 'Khojki', 'Khudawadi', 'Kirat_Rai', 'Lao', 'Latin',
  'Lepcha', 'Limbu', 'Linear_A', 'Linear_B', 'Lisu', 'Lycian', 'Lydian', 'Mahajani', 'Makasar',
  'Malayalam', 'Mandaic', 'Manichaean', 'Marchen', 'Masaram_Gondi', 'Medefaidrin', 'Meetei_Mayek',
  'Mende_Kikakui', 'Meroitic_Cursive', 'Meroitic_Hieroglyphs', 'Miao', 'Modi', 'Mongolian', 'Mro',
  'Multani', 'Myanmar', 'Nabataean', 'Nag_Mundari', 'Nandinagari', 'New_Tai_Lue', 'Newa', 'Nko',
  'Nushu', 'Nyiakeng_Puachue_Hmong', 'Ogham', 'Ol_Chiki', 'Ol_Onal', 'Old_Hungarian', 'Old_Italic',
  'Old_North_Arabian', 'Old_Permic', 'Old_Persian', 'Old_Sogdian', 'Old_South_Arabian',
  'Old_Turkic', 'Old_Uyghur', 'Oriya', 'Osage', 'Osmanya', 'Pahawh_Hmong', 'Palmyrene',
  'Pau_Cin_Hau', 'Phags_Pa', 'Phoenician', 'Psalter_Pahlavi', 'Rejang', 'Runic', 'Samaritan',
  'Saurashtra', 'Sharada', 'Shavian', 'Siddham', 'SignWriting', 'Sinhala', 'Sogdian',
  'Sora_Sompeng', 'Soyombo', 'Sundanese', 'Sunuwar', 'Syloti_Nagri', 'Syriac', 'Tagalog',
  'Tagbanwa', 'Tai_Le', 'Tai_Tham', 'Tai_Viet', 'Takri', 'Tamil', 'Tangsa', 'Tangut', 'Telugu',
  'Thaana', 'Thai', 'Tibetan', 'Tifinagh', 'Tirhuta', 'Todhri', 'Toto', 'Tulu_Tigalari', 'Ugaritic',
  'Vai', 'Vithkuqi', 'Wancho', 'Warang_Citi', 'Yezidi', 'Yi', 'Zanabazar_Square', 'Beria_Erfe',
  'Sidetic', 'Tai_Yo', 'Tolong_Siki',
];

const SCRIPT_TESTS = SCRIPT_NAMES.map((name) => ({ name, test: new RegExp(`^\\p{scx=${name}}$`, 'u') }));

const HIGHLY_RESTRICTIVE_SETS: ReadonlyArray<ReadonlySet<string>> = [
  new Set(['Latin', 'Han', 'Hiragana', 'Katakana']),
  new Set(['Latin', 'Han', 'Bopomofo']),
  new Set(['Latin', 'Han', 'Hangul']),
];

const scriptCache = new Map<string, ReadonlySet<string>>();

/** The scripts a code point is used with (empty for Common and Inherited only). */
export function scriptExtensions(ch: string): ReadonlySet<string> {
  let scripts = scriptCache.get(ch);
  if (!scripts) {
    scripts = new Set(SCRIPT_TESTS.filter(({ test }) => test.test(ch)).map(({ name }) => name));
    scriptCache.set(ch, scripts);
  }
  return scripts;
}

export interface ScriptMix {
  /** UTS #39 Highly Restrictive (or stricter). */
  highlyRestrictive: boolean;
  /** Scripts of the label's letters, in order of first use (for messages). */
  scripts: string[];
}

export function labelScripts(label: string): ScriptMix {
  const sets: Array<ReadonlySet<string>> = [];
  const order: string[] = [];
  for (const ch of label) {
    const scripts = scriptExtensions(ch);
    if (scripts.size === 0) continue;
    sets.push(scripts);
    if (scripts.size === 1) {
      const [only] = scripts;
      if (!order.includes(only)) order.push(only);
    }
  }
  if (sets.length === 0) return { highlyRestrictive: true, scripts: [] };
  // Single script: one script shared by every letter.
  const shared = [...sets[0]].filter((name) => sets.every((s) => s.has(name)));
  if (shared.length > 0) return { highlyRestrictive: true, scripts: order.length ? order : [shared[0]] };
  const covered = HIGHLY_RESTRICTIVE_SETS.some((allowed) => sets.every((s) => [...s].some((name) => allowed.has(name))));
  return { highlyRestrictive: covered, scripts: order };
}
