const TWIPS_PER_INCH = 1440;
const A4_PAGE_WIDTH = 11906;
const A4_PAGE_HEIGHT = 16838;
const PAGE_MARGIN = {
  top: 720,
  right: 720,
  bottom: 720,
  left: 720,
};
const CONTENT_WIDTH = A4_PAGE_WIDTH - PAGE_MARGIN.left - PAGE_MARGIN.right;

const COLORS = {
  ink: '172033',
  muted: '64748B',
  faint: 'F8FAFC',
  faintBlue: 'EFF6FF',
  border: 'D8E0EA',
  blue: '2563EB',
  deepBlue: '1E3A8A',
  navy: '0F172A',
  white: 'FFFFFF',
  codeBg: 'EEF2F7',
};

const BODY_FONT = 'Aptos';
const MONO_FONT = 'Cascadia Mono';

const halfPoint = (value) => value * 2;

const stripMarkdownInline = (value) => (
  String(value || '')
    .replace(/\\\|/g, '|')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)')
    .replace(/\s+/g, ' ')
    .trim()
);

const normalizeDocxText = (value, fallback = 'Not available') => {
  const text = stripMarkdownInline(value);
  return text || fallback;
};

const isTableLine = (line) => {
  const trimmed = line.trim();
  return trimmed.startsWith('|') && trimmed.includes('|', 1);
};

const splitMarkdownTableRow = (line) => {
  const trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  const cells = [];
  let current = '';
  let escaped = false;

  for (const char of trimmed) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === '\\') {
      escaped = true;
      continue;
    }

    if (char === '|') {
      cells.push(current.trim());
      current = '';
      continue;
    }

    current += char;
  }

  cells.push(current.trim());
  return cells;
};

const isTableSeparator = (line) => {
  if (!isTableLine(line)) return false;
  return splitMarkdownTableRow(line).every((cell) => /^:?-{3,}:?$/.test(cell.trim()));
};

const isHeadingLine = (line) => /^#{1,6}\s+\S/.test(line.trim());
const isUnorderedListLine = (line) => /^\s*[-*+]\s+\S/.test(line);
const isOrderedListLine = (line) => /^\s*\d+\.\s+\S/.test(line);
const getListLevel = (line) => Math.min(2, Math.floor((line.match(/^\s*/)?.[0].length || 0) / 2));

const parseMarkdownBlocks = (markdownText) => {
  const lines = String(markdownText || '').replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];

    if (!line.trim()) {
      index += 1;
      continue;
    }

    const headingMatch = line.trim().match(/^(#{1,6})\s+(.+)$/);
    if (headingMatch) {
      blocks.push({
        type: 'heading',
        level: headingMatch[1].length,
        text: normalizeDocxText(headingMatch[2], ''),
      });
      index += 1;
      continue;
    }

    if (isTableLine(line) && isTableSeparator(lines[index + 1] || '')) {
      const headers = splitMarkdownTableRow(line).map((cell) => normalizeDocxText(cell));
      index += 2;
      const rows = [];

      while (index < lines.length && isTableLine(lines[index])) {
        rows.push(splitMarkdownTableRow(lines[index]).map((cell) => normalizeDocxText(cell)));
        index += 1;
      }

      blocks.push({ type: 'table', headers, rows });
      continue;
    }

    if (isUnorderedListLine(line) || isOrderedListLine(line)) {
      const ordered = isOrderedListLine(line);
      const items = [];

      while (
        index < lines.length
        && ((ordered && isOrderedListLine(lines[index])) || (!ordered && isUnorderedListLine(lines[index])))
      ) {
        const itemLine = lines[index];
        items.push({
          text: normalizeDocxText(itemLine.replace(/^\s*(?:[-*+]|\d+\.)\s+/, '')),
          level: getListLevel(itemLine),
        });
        index += 1;
      }

      blocks.push({ type: ordered ? 'orderedList' : 'unorderedList', items });
      continue;
    }

    const paragraphLines = [];
    while (
      index < lines.length
      && lines[index].trim()
      && !isHeadingLine(lines[index])
      && !(isTableLine(lines[index]) && isTableSeparator(lines[index + 1] || ''))
      && !isUnorderedListLine(lines[index])
      && !isOrderedListLine(lines[index])
    ) {
      paragraphLines.push(lines[index].trim());
      index += 1;
    }

    blocks.push({
      type: 'paragraph',
      text: normalizeDocxText(paragraphLines.join(' '), ''),
    });
  }

  return blocks.filter((block) => block.text !== '' || block.headers || block.items);
};

const extractReportShell = (blocks, fallbackTitle) => {
  const titleBlockIndex = blocks.findIndex((block) => block.type === 'heading');
  const titleBlock = titleBlockIndex >= 0 ? blocks[titleBlockIndex] : null;
  const title = titleBlock?.text || fallbackTitle || 'Detection and Analysis';
  const bodyBlocks = [...blocks];

  if (titleBlockIndex >= 0) {
    bodyBlocks.splice(titleBlockIndex, 1);
  }

  const metadataIndex = bodyBlocks.findIndex((block, index) => (
    index <= 1
    && block.type === 'unorderedList'
    && block.items.some((item) => item.text.includes(':'))
  ));

  const metadata = [];
  if (metadataIndex >= 0) {
    bodyBlocks[metadataIndex].items.forEach((item) => {
      const separator = item.text.indexOf(':');
      if (separator > -1) {
        metadata.push({
          label: item.text.slice(0, separator).trim(),
          value: item.text.slice(separator + 1).trim() || 'Unavailable',
        });
      }
    });
    bodyBlocks.splice(metadataIndex, 1);
  }

  return { title, metadata, bodyBlocks };
};

const createInlineRuns = (docx, value, options = {}) => {
  const { TextRun } = docx;
  const text = String(value || '');
  const size = options.size || halfPoint(10);
  const color = options.color || COLORS.ink;
  const runs = [];
  const tokenPattern = /(`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\[[^\]]+\]\((https?:\/\/[^)]+)\)|https?:\/\/\S+)/g;
  let lastIndex = 0;

  const pushPlain = (plainText) => {
    if (!plainText) return;
    runs.push(new TextRun({
      text: plainText.replace(/\\\|/g, '|'),
      font: BODY_FONT,
      size,
      color,
      bold: options.bold,
    }));
  };

  for (const match of text.matchAll(tokenPattern)) {
    pushPlain(text.slice(lastIndex, match.index));
    const token = match[0];

    if (token.startsWith('`') && token.endsWith('`')) {
      runs.push(new TextRun({
        text: token.slice(1, -1),
        font: MONO_FONT,
        size: Math.max(halfPoint(7.5), size - 1),
        color: COLORS.navy,
        shading: { fill: COLORS.codeBg },
      }));
    } else if ((token.startsWith('**') && token.endsWith('**')) || (token.startsWith('__') && token.endsWith('__'))) {
      runs.push(new TextRun({
        text: token.slice(2, -2),
        font: BODY_FONT,
        size,
        color,
        bold: true,
      }));
    } else {
      runs.push(new TextRun({
        text: stripMarkdownInline(token),
        font: BODY_FONT,
        size,
    color: COLORS.deepBlue,
        underline: {},
      }));
    }

    lastIndex = match.index + token.length;
  }

  pushPlain(text.slice(lastIndex));

  if (!runs.length) {
    runs.push(new TextRun({ text: 'Not available', font: BODY_FONT, size, color: COLORS.muted }));
  }

  return runs;
};

const paragraph = (docx, children, options = {}) => {
  const { Paragraph } = docx;
  return new Paragraph({
    children,
    alignment: options.alignment,
    border: options.border,
    heading: options.heading,
    numbering: options.numbering,
    pageBreakBefore: options.pageBreakBefore,
    keepNext: options.keepNext,
    keepLines: options.keepLines,
    wordWrap: true,
    spacing: {
      before: options.before ?? 0,
      after: options.after ?? 140,
      line: options.line ?? 260,
    },
    indent: options.indent,
    shading: options.shading,
  });
};

const textParagraph = (docx, text, options = {}) => (
  paragraph(docx, createInlineRuns(docx, text, options), options)
);

const createMetadataTable = (docx, metadata) => {
  const {
    AlignmentType,
    BorderStyle,
    Table,
    TableCell,
    TableLayoutType,
    TableRow,
    VerticalAlign,
    WidthType,
  } = docx;

  const rows = [];
  const items = metadata.length ? metadata : [{ label: 'Report', value: 'Detection and Analysis' }];

  for (let index = 0; index < items.length; index += 2) {
    const pair = items.slice(index, index + 2);
    rows.push(new TableRow({
      cantSplit: true,
      children: [0, 1].map((slot) => {
        const item = pair[slot];
        return new TableCell({
          width: { size: CONTENT_WIDTH / 2, type: WidthType.DXA },
          verticalAlign: VerticalAlign.CENTER,
          margins: { top: 90, bottom: 90, left: 120, right: 120 },
          borders: {
            top: { style: BorderStyle.SINGLE, color: COLORS.border, size: 6 },
            bottom: { style: BorderStyle.SINGLE, color: COLORS.border, size: 6 },
            left: { style: BorderStyle.SINGLE, color: COLORS.border, size: 6 },
            right: { style: BorderStyle.SINGLE, color: COLORS.border, size: 6 },
          },
          shading: { fill: COLORS.faint },
          children: item ? [
            textParagraph(docx, item.label, {
              size: halfPoint(7.5),
              color: COLORS.muted,
              bold: true,
              after: 25,
              line: 220,
            }),
            textParagraph(docx, item.value, {
              size: halfPoint(9),
              color: COLORS.ink,
              after: 0,
              line: 230,
            }),
          ] : [textParagraph(docx, '', { after: 0 })],
        });
      }),
    }));
  }

  return new Table({
    rows,
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [CONTENT_WIDTH / 2, CONTENT_WIDTH / 2],
    layout: TableLayoutType.FIXED,
    alignment: AlignmentType.START,
  });
};

const createCover = (docx, title, metadata) => {
  const {
    AlignmentType,
    BorderStyle,
    Table,
    TableCell,
    TableLayoutType,
    TableRow,
    TextRun,
    VerticalAlign,
    WidthType,
  } = docx;

  return [
    new Table({
      rows: [
        new TableRow({
          cantSplit: true,
          children: [
            new TableCell({
              width: { size: CONTENT_WIDTH, type: WidthType.DXA },
              verticalAlign: VerticalAlign.CENTER,
              shading: { fill: COLORS.navy },
              margins: { top: 360, bottom: 360, left: 420, right: 420 },
              borders: {
                top: { style: BorderStyle.SINGLE, color: COLORS.navy, size: 0 },
                bottom: { style: BorderStyle.SINGLE, color: COLORS.navy, size: 0 },
                left: { style: BorderStyle.SINGLE, color: COLORS.navy, size: 0 },
                right: { style: BorderStyle.SINGLE, color: COLORS.navy, size: 0 },
              },
              children: [
                paragraph(docx, [
                  new TextRun({
                    text: 'FIRSTPROTOTYPE DFIR REPORT',
                    font: BODY_FONT,
                    size: halfPoint(8.5),
                    bold: true,
                    color: '99F6E4',
                  }),
                ], { after: 90, line: 220 }),
                paragraph(docx, [
                  new TextRun({
                    text: title,
                    font: BODY_FONT,
                    size: halfPoint(24),
                    bold: true,
                    color: COLORS.white,
                  }),
                ], { after: 140, line: 300 }),
                paragraph(docx, [
                  new TextRun({
                    text: 'Evidence-bound investigation summary for analyst review and handoff.',
                    font: BODY_FONT,
                    size: halfPoint(10),
                    color: 'D1FAE5',
                  }),
                ], { after: 0, line: 250 }),
              ],
            }),
          ],
        }),
      ],
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [CONTENT_WIDTH],
      layout: TableLayoutType.FIXED,
      alignment: AlignmentType.START,
    }),
    paragraph(docx, [], { after: 160 }),
    createMetadataTable(docx, metadata),
    paragraph(docx, [], { after: 220 }),
  ];
};

const getTableColumnWidths = (headers, rows) => {
  const columnCount = Math.max(headers.length, ...rows.map((row) => row.length));
  const normalizedHeaders = Array.from({ length: columnCount }, (_, index) => headers[index] || '');
  const normalizedRows = rows.map((row) => Array.from({ length: columnCount }, (_, index) => row[index] || ''));

  if (columnCount === 1) return [CONTENT_WIDTH];
  if (columnCount === 2) return [Math.round(CONTENT_WIDTH * 0.32), Math.round(CONTENT_WIDTH * 0.68)];

  const weights = normalizedHeaders.map((header, columnIndex) => {
    const samples = normalizedRows.map((row) => row[columnIndex]);
    const maxLength = Math.max(header.length, ...samples.map((sample) => sample.length));
    const avgLength = samples.reduce((total, sample) => total + Math.min(sample.length, 90), 0) / Math.max(samples.length, 1);
    const shortFieldBias = /^(id|type|time|ioc|field|status|severity|confidence|evidence)$/i.test(header) ? -10 : 0;
    return Math.max(12, Math.min(42, maxLength * 0.35 + avgLength * 0.65 + shortFieldBias));
  });

  const totalWeight = weights.reduce((total, weight) => total + weight, 0);
  const minWidth = Math.round(CONTENT_WIDTH * (columnCount >= 5 ? 0.12 : 0.14));
  const maxWidth = Math.round(CONTENT_WIDTH * 0.42);
  let widths = weights.map((weight) => Math.round((weight / totalWeight) * CONTENT_WIDTH));
  widths = widths.map((width) => Math.max(minWidth, Math.min(maxWidth, width)));

  const widthTotal = widths.reduce((total, width) => total + width, 0);
  widths[widths.length - 1] += CONTENT_WIDTH - widthTotal;
  return widths;
};

const createReportTable = (docx, headers, rows) => {
  const {
    AlignmentType,
    BorderStyle,
    Table,
    TableCell,
    TableLayoutType,
    TableRow,
    VerticalAlign,
    WidthType,
  } = docx;

  const widths = getTableColumnWidths(headers, rows);
  const border = { style: BorderStyle.SINGLE, color: COLORS.border, size: 6 };
  const normalizedRows = rows.map((row) => Array.from({ length: widths.length }, (_, index) => row[index] || ''));

  const makeCell = (text, columnIndex, isHeader, rowIndex) => new TableCell({
    width: { size: widths[columnIndex], type: WidthType.DXA },
    verticalAlign: VerticalAlign.CENTER,
    margins: {
      top: isHeader ? 120 : 105,
      bottom: isHeader ? 120 : 105,
      left: 115,
      right: 115,
    },
    shading: {
    fill: isHeader ? COLORS.faintBlue : (rowIndex % 2 === 1 ? COLORS.faint : COLORS.white),
    },
    borders: {
      top: border,
      bottom: border,
      left: border,
      right: border,
    },
    children: [
      textParagraph(docx, text, {
        size: isHeader ? halfPoint(8.2) : halfPoint(7.8),
        color: isHeader ? COLORS.navy : COLORS.ink,
        bold: isHeader,
        after: 0,
        line: isHeader ? 220 : 215,
      }),
    ],
  });

  return [
    new Table({
      rows: [
        new TableRow({
          tableHeader: true,
          cantSplit: true,
          children: headers.map((header, index) => makeCell(header, index, true, 0)),
        }),
        ...normalizedRows.map((row, rowIndex) => new TableRow({
          cantSplit: true,
          children: widths.map((_, columnIndex) => makeCell(row[columnIndex], columnIndex, false, rowIndex)),
        })),
      ],
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: widths,
      layout: TableLayoutType.FIXED,
      alignment: AlignmentType.START,
    }),
    paragraph(docx, [], { after: 180 }),
  ];
};

const createHeading = (docx, block) => {
  const { BorderStyle, HeadingLevel } = docx;
  const level = Math.min(block.level, 4);

  if (level <= 2) {
    return textParagraph(docx, block.text, {
      heading: level === 1 ? HeadingLevel.HEADING_1 : HeadingLevel.HEADING_2,
      size: level === 1 ? halfPoint(17) : halfPoint(14),
    color: level === 1 ? COLORS.navy : COLORS.deepBlue,
      bold: true,
      before: level === 1 ? 180 : 260,
      after: 100,
      keepNext: true,
      border: {
      bottom: { style: BorderStyle.SINGLE, color: COLORS.blue, size: 10, space: 4 },
      },
      line: 260,
    });
  }

  return textParagraph(docx, block.text, {
    heading: level === 3 ? HeadingLevel.HEADING_3 : HeadingLevel.HEADING_4,
    size: level === 3 ? halfPoint(11.5) : halfPoint(10.5),
    color: COLORS.navy,
    bold: true,
    before: 160,
    after: 65,
    keepNext: true,
    line: 240,
  });
};

const createBodyChildren = (docx, blocks) => {
  const children = [];

  blocks.forEach((block) => {
    if (block.type === 'heading') {
      children.push(createHeading(docx, block));
      return;
    }

    if (block.type === 'paragraph') {
      children.push(textParagraph(docx, block.text, {
        size: halfPoint(9.8),
        color: COLORS.ink,
        after: 130,
        line: 265,
      }));
      return;
    }

    if (block.type === 'unorderedList' || block.type === 'orderedList') {
      const reference = block.type === 'orderedList' ? 'report-numbering' : 'report-bullets';
      block.items.forEach((item) => {
        children.push(textParagraph(docx, item.text, {
          size: halfPoint(9.4),
          color: COLORS.ink,
          after: 70,
          line: 250,
          numbering: { reference, level: Math.min(item.level, 2) },
        }));
      });
      children.push(paragraph(docx, [], { after: 80 }));
      return;
    }

    if (block.type === 'table') {
      children.push(...createReportTable(docx, block.headers, block.rows));
    }
  });

  return children;
};

const createStyles = (docx) => {
  const { AlignmentType, LevelFormat, LevelSuffix } = docx;

  return {
    styles: {
      default: {
        document: {
          run: {
            font: BODY_FONT,
            size: halfPoint(10),
            color: COLORS.ink,
          },
          paragraph: {
            spacing: { line: 260, after: 120 },
          },
        },
      },
      paragraphStyles: [
        {
          id: 'Heading1',
          name: 'Heading 1',
          basedOn: 'Normal',
          next: 'Normal',
          quickFormat: true,
          run: { font: BODY_FONT, size: halfPoint(17), bold: true, color: COLORS.navy },
          paragraph: { spacing: { before: 180, after: 100 }, keepNext: true },
        },
        {
          id: 'Heading2',
          name: 'Heading 2',
          basedOn: 'Normal',
          next: 'Normal',
          quickFormat: true,
    run: { font: BODY_FONT, size: halfPoint(14), bold: true, color: COLORS.deepBlue },
          paragraph: { spacing: { before: 260, after: 100 }, keepNext: true },
        },
        {
          id: 'Heading3',
          name: 'Heading 3',
          basedOn: 'Normal',
          next: 'Normal',
          quickFormat: true,
          run: { font: BODY_FONT, size: halfPoint(11.5), bold: true, color: COLORS.navy },
          paragraph: { spacing: { before: 160, after: 65 }, keepNext: true },
        },
      ],
    },
    numbering: {
      config: [
        {
          reference: 'report-bullets',
          levels: [0, 1, 2].map((level) => ({
            level,
            format: LevelFormat.BULLET,
            text: level === 0 ? '\u2022' : '\u25E6',
            alignment: AlignmentType.START,
            suffix: LevelSuffix.TAB,
            style: {
              paragraph: { indent: { left: 420 + level * 300, hanging: 180 } },
    run: { font: 'Symbol', color: COLORS.blue },
            },
          })),
        },
        {
          reference: 'report-numbering',
          levels: [0, 1, 2].map((level) => ({
            level,
            format: LevelFormat.DECIMAL,
            text: `%${level + 1}.`,
            alignment: AlignmentType.START,
            suffix: LevelSuffix.TAB,
            style: {
              paragraph: { indent: { left: 460 + level * 320, hanging: 220 } },
    run: { font: BODY_FONT, color: COLORS.blue, bold: true },
            },
          })),
        },
      ],
    },
  };
};

const createHeaderFooter = (docx, title) => {
  const { AlignmentType, Footer, Header, PageNumber, TextRun } = docx;

  return {
    headers: {
      default: new Header({
        children: [
          paragraph(docx, [
            new TextRun({
              text: title,
              font: BODY_FONT,
              size: halfPoint(8),
              color: COLORS.muted,
              bold: true,
            }),
          ], {
            after: 80,
            line: 220,
            border: {
              bottom: { style: docx.BorderStyle.SINGLE, color: COLORS.border, size: 4, space: 3 },
            },
          }),
        ],
      }),
    },
    footers: {
      default: new Footer({
        children: [
          paragraph(docx, [
            new TextRun({
              text: 'JejakAgent',
              font: BODY_FONT,
              size: halfPoint(8),
              color: COLORS.muted,
            }),
            new TextRun({
              text: '   Page ',
              font: BODY_FONT,
              size: halfPoint(8),
              color: COLORS.muted,
            }),
            new TextRun({
              children: [PageNumber.CURRENT],
              font: BODY_FONT,
              size: halfPoint(8),
              color: COLORS.muted,
            }),
          ], {
            alignment: AlignmentType.RIGHT,
            before: 80,
            after: 0,
            line: 220,
          }),
        ],
      }),
    },
  };
};

const getTitleFromFileName = (fileName) => (
  String(fileName || 'Detection and Analysis')
    .replace(/\.[^.]+$/, '')
    .replace(/[-_]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
);

export const createStyledReportDocxBlob = async (markdownText, fileName) => {
  const docx = await import('docx');
  const { Document, Packer, PageOrientation } = docx;
  const blocks = parseMarkdownBlocks(markdownText);
  const { title, metadata, bodyBlocks } = extractReportShell(blocks, getTitleFromFileName(fileName));
  const { styles, numbering } = createStyles(docx);
  const headerFooter = createHeaderFooter(docx, title);
  const children = [
    ...createCover(docx, title, metadata),
    ...createBodyChildren(docx, bodyBlocks),
  ];

  const document = new Document({
    title,
    creator: 'JejakAgent',
    description: 'Styled DFIR incident report export',
    styles,
    numbering,
    sections: [
      {
        properties: {
          page: {
            size: {
              width: A4_PAGE_WIDTH,
              height: A4_PAGE_HEIGHT,
              orientation: PageOrientation.PORTRAIT,
            },
            margin: {
              ...PAGE_MARGIN,
              header: Math.round(0.28 * TWIPS_PER_INCH),
              footer: Math.round(0.28 * TWIPS_PER_INCH),
            },
          },
        },
        ...headerFooter,
        children,
      },
    ],
  });

  return Packer.toBlob(document);
};
