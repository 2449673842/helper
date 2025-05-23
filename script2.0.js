// script.js

// --- 全局变量定义 ---
const COLUMN_MAPPING = {
    title: ['Article Title', 'Title', '标题', '篇名'],
    authors: ['Authors', 'Author Full Names', '作者'],
    year: ['Publication Year', 'Year', '年份', '出版年份'],
    source: ['Source Title', 'Journal', '期刊', '来源', '刊名'],
    doi: ['DOI', 'doi']
};
let disclaimerAccepted = false;
let tableData = [];
let displayedTableData = [];
let currentStatusFilter = 'all';
let currentSortColumn = null;
let currentSortDirection = 'asc';

const LOCAL_STORAGE_KEY_TABLE_DATA = 'litFinderTableDataV1';

// 全局DOM元素引用 (将在DOMContentLoaded中赋值)
let statusMessage = null;
let resultsTableBody = null;
let resultsSection = null;
let batchActionsSection = null;
let noResultsMessage = null;



// PDF查看器相关的全局变量
let pdfDoc = null;
let currentPageNum = 1;
// const pdfScale = 1.5; // ***** 重要：删除或注释掉此行旧的常量 *****
let currentPdfScale = 1.5; // ***** 新增：当前PDF的缩放比例，初始值为150% *****
const MIN_PDF_SCALE = 0.25;  // ***** 新增：最小缩放比例 (25%) *****
const MAX_PDF_SCALE = 4.0;   // ***** 新增：最大缩放比例 (400%) *****
const PDF_SCALE_INCREMENT = 0.25; // ***** 新增：每次缩放的步长 (25%) *****
let currentPdfFileObject = null;
let currentViewingArticleRowId = null;
let pdfViewerTitle = null;
let pdfCanvas = null;
let pageNumSpan = null;
let pageCountSpan = null;
let pageRendering = false;
let pageNumPending = null;
const pdfScale = 1.5;
let currentRenderTask = null;

// 框选相关的全局状态变量 (因为事件监听器在DOMContentLoaded中，但这些状态可能被其他函数引用)
let isSelecting = false;
let selectionRect = { startX: 0, startY: 0, endX: 0, endY: 0, pageNum: 0, finalX: 0, finalY: 0, finalWidth: 0, finalHeight: 0 };
let selectionCtx = null;


// --- 全局函数定义 ---
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = "none";
    if (modalId === 'pdfViewerModal') {
        console.log("Global closeModal: Cleaning up PDF resources for pdfViewerModal.");
        pdfDoc = null; currentPageNum = 1; currentPdfFileObject = null; currentViewingArticleRowId = null;
        if (pdfViewerTitle) pdfViewerTitle.textContent = "PDF 查看器";
        if (pdfCanvas) { const ctx = pdfCanvas.getContext('2d'); if (ctx) ctx.clearRect(0, 0, pdfCanvas.width, pdfCanvas.height); }
        if (pageNumSpan) pageNumSpan.textContent = '0';
        if (pageCountSpan) pageCountSpan.textContent = '0';
        const prevBtn = document.getElementById('prevPageBtn');
        const nextBtn = document.getElementById('nextPageBtn');
        if (prevBtn) prevBtn.disabled = true;
        if (nextBtn) nextBtn.disabled = true;
        // 清除选框画布和截图按钮状态
        const selCanvas = document.getElementById('selectionCanvas');
        if (selCanvas) { const selCtx = selCanvas.getContext('2d'); if (selCtx) selCtx.clearRect(0, 0, selCanvas.width, selCanvas.height); }
        const capBtn = document.getElementById('captureSelectionBtn');
        if (capBtn) capBtn.classList.add('hidden');
        isSelecting = false; // 重置选择状态
    }
}

function showStatus(message, styleClass, duration = 0) {
    console.log("[ShowStatus] Called. Message:", message, "Style:", styleClass, "Duration:", duration); // 增加日志方便调试

    if (statusMessage) { // statusMessage 是通过 getElementById('statusMessage') 获取的
        // 1. 使用 innerHTML 而不是 textContent，以允许消息中包含HTML标签（例如链接）
        statusMessage.innerHTML = message;

        statusMessage.className = `mb-6 text-center text-sm font-medium ${styleClass || 'text-gray-700'}`;

        // 2. 尝试将 statusMessage 置于模态框之上
        // 需要确保 statusMessage 元素在CSS中可以被定位 (例如 position: fixed, relative, absolute)
        // 并且其父元素没有更低的 z-index 或创建新的堆叠上下文。
        // 一个简单的尝试是直接设置 z-index。
        // 注意：如果 statusMessage 的 position 是 static (默认值)，z-index 可能无效。
        // 为了更可靠，可以考虑给 statusMessage 添加一个class，该class定义 position 和高 z-index。
        // 或者，如果 statusMessage 是 body 的直接子元素，这样设置通常有效：
        statusMessage.style.position = 'fixed'; // 或者 'absolute'，取决于您希望它如何定位
        statusMessage.style.left = '50%';
        statusMessage.style.transform = 'translateX(-50%)';
        statusMessage.style.bottom = '20px'; // 或者 'top: 20px;'，根据您的喜好
        statusMessage.style.zIndex = '1051'; // 比模态框的 z-index (通常是1050或类似) 和其背景板更高
                                         // 您的模态框 z-index 是 50，背景板可能是 49。所以 51 或更高应该可以。
                                         // 我在之前的HTML中看到您的 modal z-index: 50，所以这里用 51 或 100 都可以。

        // 使其可见（如果它默认是隐藏的，或者被之前的 className 清除了可见性）
        statusMessage.style.display = 'block';


        if (duration > 0) {
            // 为了避免旧的setTimeout错误地清除了新的消息，
            // 我们可以考虑在设置新消息时，清除任何可能存在的旧的setTimeout。
            // 这需要一个全局变量来保存 setTimeout 的ID。
            // 为简单起见，我们暂时保留原有的清除逻辑，但注意其潜在问题。
            // const currentMessageForTimeout = message; // 捕获当前消息
            setTimeout(() => {
                // 理想情况下，我们应该检查是否仍然是这条消息触发的清除操作
                // if (statusMessage.innerHTML === currentMessageForTimeout) { // 比较 innerHTML

                // 简化：只要时间到了就清除，如果在此期间有新消息，新消息的timeout会负责它的清除
                statusMessage.innerHTML = '';
                statusMessage.className = 'mb-6 text-center min-h-[20px]'; // 恢复基本样式
                statusMessage.style.zIndex = ''; // 重置 z-index
                statusMessage.style.display = 'none'; // 操作完成后可以隐藏，避免空元素占据空间
                statusMessage.style.position = ''; // 重置 position
                statusMessage.style.left = '';
                statusMessage.style.transform = '';
                statusMessage.style.bottom = '';


                // }
            }, duration);
        }
    } else {
        console.warn("showStatus called before statusMessage element init. Msg:", message);
    }
}

function closeModalAndAcceptDisclaimer() {
    disclaimerAccepted = true;
    closeModal('disclaimerModal');
    showStatus('免责声明已接受。您现在可以处理文件了。', 'text-green-500');
}

function truncateText(text, maxLength) {
    if (!text) return 'N/A';
    const strText = String(text);
    return strText.length > maxLength ? strText.substring(0, maxLength) + '...' : strText;
}
// script.js 全局作用域 (例如，放在其他全局辅助函数如 truncateText 附近)

// <--- 全局函数 sanitizeFilenameForMatching 开始 ---
function sanitizeFilenameForMatching(filenameBase) {
    if (!filenameBase) {
        return "untitled_document"; // 或者返回空，取决于匹配策略
    }
    let sanitized = String(filenameBase);
    // 移除或替换非法字符，与后端 sanitize_filename 核心逻辑一致
    sanitized = sanitized.replace(/[/\\]/g, '_');        // 替换路径分隔符
    sanitized = sanitized.replace(/[<>:"|?*]/g, '_');    // 移除Windows非法字符等
    sanitized = sanitized.replace(/[\s_]+/g, '_');       // 多个空格或下划线变单个
    sanitized = sanitized.replace(/^[_.]+|[_.]+$/g, ''); // 移除首尾特殊字符

    // 后端有限制长度并可能在下划线处截断，前端这里可以先简单截断
    // 或者，如果后端ZIP包里的文件名就是按这个规则生成的，前端也要完全一致
    // 为了匹配，我们先假设后端也是净化后直接用，没有复杂的截断逻辑，或者截断规则对匹配影响不大
    // 如果后端命名规则复杂，这里需要完全同步
    const maxLength = 100; // 与后端Python中的 max_len_base 保持一致
    if (sanitized.length > maxLength) {
        sanitized = sanitized.substring(0, maxLength); // 初步硬截断
        // 尝试在截断处找到最后一个下划线
        const lastUnderscore = sanitized.lastIndexOf('_');
        // 后端Python的条件是 last_underscore > max_len_base / 2
        // 我们也用类似的逻辑，确保截断点不是太靠前
        if (lastUnderscore > maxLength / 2) {
            sanitized = sanitized.substring(0, lastUnderscore);
        }
    }
    if (!sanitized) {
        return "document";
    }
    return sanitized;
}
// <--- 全局函数 sanitizeFilenameForMatching 结束 ---
function findHeader(headers, possibleNames) {
    if (!headers || headers.length === 0 || !possibleNames || possibleNames.length === 0) return null;
    const lowerCaseHeaders = headers.map(h => String(h).toLowerCase().trim());
    for (const name of possibleNames) {
        const lowerCaseName = name.toLowerCase().trim();
        const index = lowerCaseHeaders.indexOf(lowerCaseName);
        if (index !== -1) return headers[index];
    }
    return null;
}

function escapeCsvCell(cellData) {
    if (cellData == null) return '';
    const stringData = String(cellData);
    if (stringData.includes(',') || stringData.includes('"') || stringData.includes('\n') || stringData.includes('\r')) {
        return `"${stringData.replace(/"/g, '""')}"`;
    }
    return stringData;
}

function exportTableDataToCSV() {
    if (!tableData || tableData.length === 0) { showStatus('没有数据可供导出。', 'text-yellow-500', 3000); return; }
    showStatus('正在准备CSV文件...', 'text-blue-500');
    const columnsToExport = [
        { key: 'title', displayName: 'Title' }, { key: 'authors', displayName: 'Authors' },
        { key: 'year', displayName: 'Year' }, { key: 'source', displayName: 'Source/Journal' },
        { key: 'doi', displayName: 'DOI' },
    ];
    const firstRowKeys = (tableData.length > 0 && tableData[0]) ? Object.keys(tableData[0]) : [];
    const actualHeaderNames = {};
    columnsToExport.forEach(col => { actualHeaderNames[col.key] = findHeader(firstRowKeys, COLUMN_MAPPING[col.key] || [col.key]); });
    let csvContent = "\uFEFF";
    const headerDisplayNames = columnsToExport.map(col => escapeCsvCell(col.displayName));
    headerDisplayNames.push(escapeCsvCell('PDF Link')); headerDisplayNames.push(escapeCsvCell('Status'));
    csvContent += headerDisplayNames.join(',') + '\r\n';
    tableData.forEach(row => {
        const rowValues = columnsToExport.map(col => {
            const actualKey = actualHeaderNames[col.key];
            return escapeCsvCell(actualKey && row[actualKey] !== undefined ? row[actualKey] : '');
        });
        rowValues.push(escapeCsvCell(row.pdfLink || '')); rowValues.push(escapeCsvCell(row.status || ''));
        csvContent += rowValues.join(',') + '\r\n';
    });
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement("a");
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
        link.setAttribute("href", url);
        link.setAttribute("download", `literature_export_${timestamp}.csv`);
        link.style.visibility = 'hidden'; document.body.appendChild(link); link.click(); document.body.removeChild(link); URL.revokeObjectURL(url);
        showStatus('CSV文件已开始下载。', 'text-green-500', 4000);
    } else { showStatus('您的浏览器不支持直接下载。', 'text-red-500', 4000); }
}

function sanitizeFilenameForImage(namePart) { // Renamed for clarity
    if (!namePart) return "image";
    let sanitized = String(namePart);
    sanitized = sanitized.replace(/[/\\]/g, '_');
    sanitized = sanitized.replace(/[<>:"|?*]/g, '_');
    sanitized = sanitized.replace(/[\s_]+/g, '_');
    // .strip() is not a standard String method. Use trim() or regex for stripping.
    sanitized = sanitized.replace(/^[_.]+|[_.]+$/g, ''); // Strip leading/trailing _ or .
    return sanitized.substring(0, 50); // Limit length
}


// --- DOMContentLoaded 事件监听器 ---
document.addEventListener('DOMContentLoaded', () => {
    // --- DOM元素获取与赋值给全局变量 ---
    statusMessage = document.getElementById('statusMessage');
    resultsTableBody = document.getElementById('resultsTableBody');
    resultsSection = document.getElementById('resultsSection');
    batchActionsSection = document.getElementById('batchActionsSection');
    noResultsMessage = document.getElementById('noResultsMessage');
    pdfViewerTitle = document.getElementById('pdfViewerTitle');
    pdfCanvas = document.getElementById('pdfCanvas');
    pageNumSpan = document.getElementById('page_num');
    pageCountSpan = document.getElementById('page_count');

    // --- 其他在 DOMContentLoaded 中定义的 const 变量 (局部作用域) ---
    // 在 DOMContentLoaded 顶部
    const zoomOutBtn = document.getElementById('zoomOutBtn');
    const zoomInBtn = document.getElementById('zoomInBtn');
    const zoomLevelSpan = document.getElementById('zoomLevelSpan');
    const fullscreenBtn = document.getElementById('fullscreenBtn');
    const pdfViewerModalContent = document.getElementById('pdfViewerModalContent'); // 这是我们要全屏的元素
    const currentArticleScreenshotsDiv = document.getElementById('currentArticleScreenshots');
    const screenshotsListContainer = document.getElementById('screenshotsListContainer');
    const noScreenshotsMessage = document.getElementById('noScreenshotsMessage');
    const disclaimerModal = document.getElementById('disclaimerModal');
    const failedListModal = document.getElementById('failedListModal');
    const fileInput = document.getElementById('fileInput');
    const processFileButton = document.getElementById('processFileButton');
    const sciHubDomainSelect = document.getElementById('sciHubDomainSelect');
    const customSciHubUrlInputContainer = document.getElementById('customSciHubUrlInputContainer');
    const customSciHubUrlInput = document.getElementById('customSciHubUrlInput');
    const backendApiUrlInput = document.getElementById('backendApiUrlInput');
    const downloadAllButton = document.getElementById('downloadAllButton');
    const showFailedButton = document.getElementById('showFailedButton');
    const autoFindAllButton = document.getElementById('autoFindAllButton');
    const failedItemsTableContainer = document.getElementById('failedItemsTableContainer');
    const noFailedItemsMessageElem = document.getElementById('noFailedItemsMessage');
    const batchProgressContainer = document.getElementById('batchProgressContainer');
    const batchProgressBar = document.getElementById('batchProgressBar');
    const batchProgressText = document.getElementById('batchProgressText');
    const exportCsvButtonFromDOM = document.getElementById('exportCsvButton'); // Renamed to avoid conflict if any
    const statusFilterSelect = document.getElementById('statusFilterSelect');
    const resetFiltersButton = document.getElementById('resetFiltersButton');
    const clearLocalStorageButton = document.getElementById('clearLocalStorageButton');
    const downloadTemplateButton = document.getElementById('downloadTemplateButton');
    const templateInfoIcon = document.getElementById('templateInfoIcon');
    const templateTooltip = document.getElementById('templateTooltip');
    const tooltipContentList = document.getElementById('tooltipContentList');
    const batchZipProcessingLoader = document.getElementById('batchZipProcessingLoader');
    const pdfViewerModal = document.getElementById('pdfViewerModal');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const pdfFilePicker = document.getElementById('pdfFilePicker');
    const openPdfFileBtn = document.getElementById('openPdfFileBtn');
    const captureSelectionBtn = document.getElementById('captureSelectionBtn');
    const selectionCanvas = document.getElementById('selectionCanvas');
    const pdfCanvasContainer = document.getElementById('pdfCanvasContainer');
    const linkLocalPdfsButton = document.getElementById('linkLocalPdfsButton');     // <-- 新增
    const localPdfFolderPicker = document.getElementById('localPdfFolderPicker'); // <-- 新增
    const linkLocalPdfsInfoIcon = document.getElementById('linkLocalPdfsInfoIcon'); // <-- 新增 (用于tooltip)
    const linkLocalPdfsTooltip = document.getElementById('linkLocalPdfsTooltip');   // <-- 新增 (用于tooltip)
    const editScreenshotModal = document.getElementById('editScreenshotModal');             // <-- 新增
    const editScreenshotModalTitle = document.getElementById('editScreenshotModalTitle'); // <-- 新增 (模态框标题，如果需要动态改)
    const editSsArticleIdSpan = document.getElementById('editSsArticleId');             // <-- 新增
    const editSsIdSpan = document.getElementById('editSsId');                         // <-- 新增
    const editSsFilenameSpan = document.getElementById('editSsFilename');               // <-- 新增
    const editingScreenshotArticleIdInput = document.getElementById('editingScreenshotArticleId'); // <-- 新增
    const editingScreenshotIdInput = document.getElementById('editingScreenshotId');         // <-- 新增
    const editSsChartTypeSelect = document.getElementById('editSsChartType');         // <-- 新增
    const editSsDescriptionTextarea = document.getElementById('editSsDescription');     // <-- 新增
    const cancelEditSsButton = document.getElementById('cancelEditSsButton');         // <-- 新增
    const saveEditSsButton = document.getElementById('saveEditSsButton');             // <-- 新增
    const toggleScreenshotsPanelBtn = document.getElementById('toggleScreenshotsPanelBtn');
    const pdfViewColumn = document.getElementById('pdfViewColumn');
    const screenshotsColumn = document.getElementById('screenshotsColumn');
    // --- 初始化和加载本地存储 ---
    if (disclaimerModal) disclaimerModal.style.display = 'block';

    if (typeof pdfjsLib !== 'undefined') {
        // 使用您本地的PDF.js文件路径
        pdfjsLib.GlobalWorkerOptions.workerSrc = '../pdf.js/build/pdf.worker.js'; // 确保路径正确
        console.log("PDF.js worker SRC configured to LOCAL path:", pdfjsLib.GlobalWorkerOptions.workerSrc);
    } else {
        console.error("PDF.js library (pdfjsLib) not loaded! PDF functionality will be unavailable.");
        showStatus("PDF.js核心库未能加载，PDF相关功能无法使用。", "text-red-500");
    }

    const savedBackendApiUrl = localStorage.getItem('litfinderBackendApiUrl');
    if (savedBackendApiUrl && backendApiUrlInput) backendApiUrlInput.value = savedBackendApiUrl;

    const savedSciHubDomain = localStorage.getItem('litfinderSciHubDomain');
    const savedSciHubCustomUrl = localStorage.getItem('litfinderSciHubCustomUrl');
    if (savedSciHubDomain && sciHubDomainSelect) {
        sciHubDomainSelect.value = savedSciHubDomain;
        if (savedSciHubDomain === 'custom') {
            if(customSciHubUrlInputContainer) customSciHubUrlInputContainer.style.display = 'block';
            if (savedSciHubCustomUrl && customSciHubUrlInput) customSciHubUrlInput.value = savedSciHubCustomUrl;
        } else {
            if(customSciHubUrlInputContainer) customSciHubUrlInputContainer.style.display = 'none';
        }
    }


    if (fullscreenBtn && pdfViewerModalContent) {
        function updateFullscreenButton(isFullscreen) {
            if (isFullscreen) {
                fullscreenBtn.innerHTML = '<i class="fas fa-compress"></i>'; // 退出全屏图标
                fullscreenBtn.title = '退出全屏';
            } else {
                fullscreenBtn.innerHTML = '<i class="fas fa-expand"></i>'; // 进入全屏图标
                fullscreenBtn.title = '切换全屏';
            }
        }

        fullscreenBtn.addEventListener('click', () => {
            if (!document.fullscreenElement) { // 如果当前没有元素在全屏
                pdfViewerModalContent.requestFullscreen().catch(err => {
                    alert(`无法进入全屏模式: ${err.message} (${err.name})`);
                    console.error("Error attempting to enable full-screen mode:", err);
                });
            } else { // 如果已在全屏模式
                if (document.exitFullscreen) {
                    document.exitFullscreen();
                }
            }
        });

        // 监听全屏状态变化事件 (包括按 ESC 键退出全屏的情况)
        document.addEventListener('fullscreenchange', () => {
            updateFullscreenButton(!!document.fullscreenElement);
        });
        // 对于一些旧浏览器可能需要前缀
        document.addEventListener('webkitfullscreenchange', () => updateFullscreenButton(!!document.webkitFullscreenElement));
        document.addEventListener('mozfullscreenchange', () => updateFullscreenButton(!!document.mozFullScreenElement));
        document.addEventListener('MSFullscreenChange', () => updateFullscreenButton(!!document.msFullscreenElement));


        // 初始化按钮状态 (页面加载时，肯定不是全屏状态)
        updateFullscreenButton(false);
    }
    // --- 事件监听器设置 ---
    // (确保所有DOM元素获取后再添加监听器)
    if (backendApiUrlInput) backendApiUrlInput.addEventListener('change', function() { localStorage.setItem('litfinderBackendApiUrl', this.value); showStatus('后端API链接已保存。', 'text-blue-500', 3000); });
    if (sciHubDomainSelect) sciHubDomainSelect.addEventListener('change', function() { const sel = this.value; localStorage.setItem('litfinderSciHubDomain', sel); if (sel === 'custom') { if(customSciHubUrlInputContainer) customSciHubUrlInputContainer.style.display = 'block'; if(customSciHubUrlInput) {customSciHubUrlInput.focus(); localStorage.setItem('litfinderSciHubCustomUrl', customSciHubUrlInput.value);}} else { if(customSciHubUrlInputContainer) customSciHubUrlInputContainer.style.display = 'none';} showStatus('Sci-Hub偏好已保存。', 'text-blue-500', 3000); });
    if (customSciHubUrlInput) customSciHubUrlInput.addEventListener('change', function() { if (sciHubDomainSelect && sciHubDomainSelect.value === 'custom') { localStorage.setItem('litfinderSciHubCustomUrl', this.value); showStatus('Sci-Hub自定义链接已保存。', 'text-blue-500', 3000); } });
    if (processFileButton) processFileButton.addEventListener('click', () => { if (!disclaimerAccepted) { alert('请先接受免责声明。'); if (disclaimerModal) disclaimerModal.style.display = 'block'; return; } if (!fileInput.files || fileInput.files.length === 0) { showStatus('请选择文件。', 'text-red-500'); return; } handleFile(fileInput.files[0]); });
    if (downloadAllButton) downloadAllButton.addEventListener('click', downloadAllAvailablePdfs);
    if (showFailedButton) showFailedButton.addEventListener('click', showFailedItemsModal);
    if (autoFindAllButton) autoFindAllButton.addEventListener('click', autoFindAllPdfs);
    if (exportCsvButtonFromDOM) exportCsvButtonFromDOM.addEventListener('click', exportTableDataToCSV); // 使用 exportCsvButtonFromDOM
    if (statusFilterSelect) statusFilterSelect.addEventListener('change', function() { currentStatusFilter = this.value; applyFiltersAndSort(); });
    if (resetFiltersButton) resetFiltersButton.addEventListener('click', () => { currentStatusFilter = 'all'; if (statusFilterSelect) statusFilterSelect.value = 'all'; currentSortColumn = null; currentSortDirection = 'asc'; applyFiltersAndSort(); showStatus('筛选排序已重置。', 'text-blue-500', 2000); });
    if (clearLocalStorageButton) clearLocalStorageButton.addEventListener('click', () => { if (confirm('确定清除所有本地保存的文献数据和设置吗？')) { localStorage.removeItem(LOCAL_STORAGE_KEY_TABLE_DATA); localStorage.removeItem('litfinderBackendApiUrl'); localStorage.removeItem('litfinderSciHubDomain'); localStorage.removeItem('litfinderSciHubCustomUrl'); tableData = []; displayedTableData = []; currentStatusFilter = 'all'; currentSortColumn = null; currentSortDirection = 'asc'; if(statusFilterSelect) statusFilterSelect.value = 'all'; if(resultsTableBody) resultsTableBody.innerHTML = ''; if(resultsSection) resultsSection.classList.add('hidden'); if(batchActionsSection) batchActionsSection.classList.add('hidden'); if(noResultsMessage) { noResultsMessage.textContent = '本地缓存已清除。'; noResultsMessage.classList.remove('hidden');} applyFiltersAndSort(); showStatus('本地缓存已清除！', 'text-green-500', 3000); } });
    if (downloadTemplateButton) downloadTemplateButton.addEventListener('click', downloadUploadTemplate);
    if (templateInfoIcon && templateTooltip && tooltipContentList) { let tooltipHTML = ''; for (const key in COLUMN_MAPPING) { if (COLUMN_MAPPING.hasOwnProperty(key)) { let displayName = key.charAt(0).toUpperCase() + key.slice(1); if (key === 'doi') displayName = 'DOI'; if (key === 'source') displayName = 'Source/Journal'; tooltipHTML += `<div class="mb-1"><strong class="text-gray-900">${displayName}:</strong> `; tooltipHTML += COLUMN_MAPPING[key].map(name => `<code>${name}</code>`).join(', '); tooltipHTML += `</div>`; } } tooltipContentList.innerHTML = tooltipHTML; let tooltipVisible = false; let tooltipTimeout; function showTooltipFunc() { clearTimeout(tooltipTimeout); templateTooltip.classList.remove('hidden'); templateTooltip.classList.add('active'); tooltipVisible = true; } function hideTooltipFunc(immediate = false) { if (immediate) { templateTooltip.classList.add('hidden'); templateTooltip.classList.remove('active'); tooltipVisible = false; } else { tooltipTimeout = setTimeout(() => { templateTooltip.classList.add('hidden'); templateTooltip.classList.remove('active'); tooltipVisible = false; }, 200); } } templateInfoIcon.addEventListener('mouseenter', showTooltipFunc); templateInfoIcon.addEventListener('mouseleave', () => hideTooltipFunc()); templateTooltip.addEventListener('mouseenter', () => clearTimeout(tooltipTimeout)); templateTooltip.addEventListener('mouseleave', () => hideTooltipFunc()); templateInfoIcon.addEventListener('click', (event) => { event.stopPropagation(); tooltipVisible ? hideTooltipFunc(true) : showTooltipFunc(); }); document.addEventListener('click', (event) => { if (tooltipVisible && templateTooltip && !templateTooltip.contains(event.target) && event.target !== templateInfoIcon) { hideTooltipFunc(true); } });}



    let isScreenshotsPanelVisible = true; // 假设默认截图列表是可见的
     // --- 新增开始: PDF查看器截图列表侧边栏切换逻辑 --
    if (toggleScreenshotsPanelBtn && pdfViewColumn && screenshotsColumn) {
        // 初始化按钮状态（如果默认可见）
        toggleScreenshotsPanelBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
        toggleScreenshotsPanelBtn.title = '隐藏截图列表';
        // 如果希望默认隐藏，则在这里初始化为隐藏状态：
        // isScreenshotsPanelVisible = false;
        // screenshotsColumn.style.width = '0px';
        // screenshotsColumn.style.borderLeft = 'none';
        // toggleScreenshotsPanelBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
        // toggleScreenshotsPanelBtn.title = '显示截图列表';


        toggleScreenshotsPanelBtn.addEventListener('click', () => {
            isScreenshotsPanelVisible = !isScreenshotsPanelVisible;
            if (isScreenshotsPanelVisible) {
                screenshotsColumn.style.width = '280px'; // 恢复到默认宽度 (可调整)
                screenshotsColumn.style.borderLeft = '1px solid #CBD5E0'; // 恢复左边框
                toggleScreenshotsPanelBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
                toggleScreenshotsPanelBtn.title = '隐藏截图列表';
            } else {
                screenshotsColumn.style.width = '0px';
                screenshotsColumn.style.borderLeft = 'none'; // 隐藏时也隐藏边框
                toggleScreenshotsPanelBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
                toggleScreenshotsPanelBtn.title = '显示截图列表';
            }

            // 可选：如果PDF canvas渲染需要精确知道其容器宽度，
            // 在切换后，如果发现canvas显示不正常，可能需要在这里延迟一小段时间后
            // 重新调用 renderPdfPage(currentPageNum) 来强制重绘以适应新的列宽。
            // 但多数情况下，CSS的flex布局和canvas自身的显示属性应该能处理。
            // 例如: setTimeout(() => { if (pdfDoc && currentPageNum) renderPdfPage(currentPageNum); }, 350); // 350ms 等待动画完成
        });
    }
    // --- 新增结束 ---
    // --- 编辑截图信息模态框的按钮事件 ---
    if (saveEditSsButton && editingScreenshotArticleIdInput && editingScreenshotIdInput && editSsChartTypeSelect && editSsDescriptionTextarea) {
        saveEditSsButton.addEventListener('click', () => {
            const articleId = editingScreenshotArticleIdInput.value;
            const screenshotId = editingScreenshotIdInput.value;
            const newChartType = editSsChartTypeSelect.value;
            const newDescription = editSsDescriptionTextarea.value.trim();
            const newWpdData = document.getElementById('editSsWpdDataTextarea').value.trim(); // Get WPD data

            if (!articleId || !screenshotId) {
                alert("错误：无法确定要保存哪个截图的信息。请关闭重试。");
                return;
            }

            const articleIndex = tableData.findIndex(row => row._id === articleId);
            if (articleIndex > -1 && tableData[articleIndex].screenshots) {
                const screenshotIndex = tableData[articleIndex].screenshots.findIndex(ss => ss.id === screenshotId);
                if (screenshotIndex > -1) {
                    // 更新 tableData 中的数据
                    tableData[articleIndex].screenshots[screenshotIndex].chartType = newChartType;
                    tableData[articleIndex].screenshots[screenshotIndex].description = newDescription;
                    tableData[articleIndex].screenshots[screenshotIndex].wpdData = newWpdData; // Save WPD data

                    saveTableDataToLocalStorage();         // 保存到 localStorage
                    displayScreenshotsForCurrentArticle(); // 刷新PDF查看器下方的截图列表

                    closeModal('editScreenshotModal');     // 关闭编辑模态框
                    showStatus(`截图信息已更新 (ID: ${truncateText(screenshotId,10)})。`, "text-green-500", 3000);
                } else {
                    alert("错误：保存失败，未找到对应的截图记录。");
                }
            } else {
                alert("错误：保存失败，未找到对应的文献记录。");
            }
        });
    }

    if (cancelEditSsButton) {
        cancelEditSsButton.addEventListener('click', () => {
            closeModal('editScreenshotModal');
        });
    }
    // --- 编辑截图信息模态框按钮事件结束 ---

    if (zoomInBtn) { // zoomInBtn 是在 DOMContentLoaded 顶部获取的 const 变量
        zoomInBtn.addEventListener('click', () => {
            if (!pdfDoc || pageRendering) return; // 如果没有文档或正在渲染，则不执行操作

            if (currentPdfScale < MAX_PDF_SCALE) {
                currentPdfScale = parseFloat((currentPdfScale + PDF_SCALE_INCREMENT).toFixed(2));
                // 再次确保不超过最大值，因为浮点数加法可能略微超过
                if (currentPdfScale > MAX_PDF_SCALE) {
                    currentPdfScale = MAX_PDF_SCALE;
                }

                console.log(`Zoom In clicked, new scale: ${currentPdfScale}`);
                updateZoomControls(); // 立即更新UI反馈
                queueRenderPage(currentPageNum); // 请求使用新比例重新渲染当前页
            }
        });
    }

    if (zoomOutBtn) { // zoomOutBtn 是在 DOMContentLoaded 顶部获取的 const 变量
        zoomOutBtn.addEventListener('click', () => {
            if (!pdfDoc || pageRendering) return; // 如果没有文档或正在渲染，则不执行操作

            if (currentPdfScale > MIN_PDF_SCALE) {
                currentPdfScale = parseFloat((currentPdfScale - PDF_SCALE_INCREMENT).toFixed(2));
                // 再次确保不低于最小值
                if (currentPdfScale < MIN_PDF_SCALE) {
                    currentPdfScale = MIN_PDF_SCALE;
                }

                console.log(`Zoom Out clicked, new scale: ${currentPdfScale}`);
                updateZoomControls(); // 立即更新UI反馈
                queueRenderPage(currentPageNum); // 请求使用新比例重新渲染当前页
            }
        });
    }


    // PDF Viewer Event Listeners
    if(prevPageBtn) prevPageBtn.addEventListener('click', onPrevPage);
    if(nextPageBtn) nextPageBtn.addEventListener('click', onNextPage);
    if(pdfFilePicker) pdfFilePicker.addEventListener('change', handlePdfFileSelected);
    if(openPdfFileBtn && pdfFilePicker) { openPdfFileBtn.addEventListener('click', () => { pdfFilePicker.value = null; pdfFilePicker.click(); });}
    // --- 新增：关联本地PDF文件夹的逻辑 ---
    if (linkLocalPdfsButton && localPdfFolderPicker) {
        linkLocalPdfsButton.addEventListener('click', () => {
            localPdfFolderPicker.value = null; // 清空以便能重复选择同一文件夹
            localPdfFolderPicker.click();
        });

        localPdfFolderPicker.addEventListener('change', async (event) => { // 可以设为 async 以便未来扩展
            const files = event.target.files;
            if (!files || files.length === 0) {
                showStatus("您没有选择文件夹，或者文件夹为空。", "text-yellow-500", 3000);
                return;
            }

            showStatus(`正在处理选择的文件夹中的 ${files.length} 个文件...`, "text-blue-500");
            await new Promise(resolve => setTimeout(resolve, 50)); // 给UI一点时间更新

            let matchedCount = 0;
            let unmatchedFileNames = []; // 记录文件夹中未匹配上的文件名

            // 将FileList转换为数组，并创建文件名到File对象的映射，方便查找
            const localFileMap = new Map();
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                if (file.name.toLowerCase().endsWith('.pdf')) { // 只处理PDF文件
                    localFileMap.set(file.name, file);
                }
            }
            console.log("[LinkLocalPDFs] Found local PDF files in folder:", Array.from(localFileMap.keys()));


            tableData.forEach(rowData => {
                if (rowData.localPdfFileObject) { // 如果已经通过其他方式关联了，暂时跳过或给出提示
                    // console.log(`Row ${rowData._id} already has a local PDF linked.`);
                    // return;
                }

                const titleHeader = findHeader(Object.keys(rowData), COLUMN_MAPPING.title);
                const articleTitle = rowData[titleHeader] ? String(rowData[titleHeader]).trim() : null;

                if (articleTitle) {
                    const expectedFilenameBase = sanitizeFilenameForMatching(articleTitle);
                    const expectedFilename = expectedFilenameBase + ".pdf";

                    // console.log(`[LinkLocalPDFs] Trying to match: '${expectedFilename}' for article title: '${articleTitle}'`);

                    if (localFileMap.has(expectedFilename)) {
                        rowData.localPdfFileObject = localFileMap.get(expectedFilename); // 存储File对象
                        // rowData.status = "本地PDF已关联"; // 可以考虑更新状态
                        matchedCount++;
                        console.log(`[LinkLocalPDFs] Matched: '${expectedFilename}' with row ${rowData._id}`);
                        localFileMap.delete(expectedFilename); // 从map中移除已匹配的，方便后续识别未匹配文件
                    }
                }
            });

            unmatchedFileNames = Array.from(localFileMap.keys()); // 剩余的就是未匹配的

            if (matchedCount > 0) {
                applyFiltersAndSort(); // 刷新表格（如果状态或其他显示需要更新）
                saveTableDataToLocalStorage(); // 保存包含 localPdfFileObject 的 tableData
            }

            let finalMessage = `成功自动关联了 ${matchedCount} 个本地PDF文件。`;
            if (unmatchedFileNames.length > 0) {
                finalMessage += ` 文件夹中还有 ${unmatchedFileNames.length} 个PDF文件未能自动匹配。`;
                console.log("[LinkLocalPDFs] Unmatched local PDF files:", unmatchedFileNames);
                // 未来可以在这里提示用户进行手动匹配
            }
            if (matchedCount === 0 && articlesToProcess.length > 0 && unmatchedFileNames.length === files.length) {
                 finalMessage = `您选择的文件夹中没有找到与当前列表文献标题匹配的PDF文件。请确保PDF文件名与文献标题（或其净化形式）一致。`;
            }


            showStatus(finalMessage, matchedCount > 0 ? "text-green-500" : "text-yellow-500", 8000);
        });
    }

    // 新增：模板信息提示框的tooltip逻辑 (如果需要，可以封装成函数)
    if (linkLocalPdfsInfoIcon && linkLocalPdfsTooltip) {
        let linkTooltipVisible = false;
        let linkTooltipTimeout;
        const showLinkTooltip = () => { clearTimeout(linkTooltipTimeout); linkLocalPdfsTooltip.classList.remove('hidden'); linkTooltipVisible = true; };
        const hideLinkTooltip = (imm = false) => { if(imm){linkLocalPdfsTooltip.classList.add('hidden'); linkTooltipVisible = false;}else{linkTooltipTimeout = setTimeout(() => {linkLocalPdfsTooltip.classList.add('hidden');linkTooltipVisible = false;}, 200);}};
        linkLocalPdfsInfoIcon.addEventListener('mouseenter', showLinkTooltip);
        linkLocalPdfsInfoIcon.addEventListener('mouseleave', () => hideLinkTooltip());
        linkLocalPdfsTooltip.addEventListener('mouseenter', () => clearTimeout(linkTooltipTimeout));
        linkLocalPdfsTooltip.addEventListener('mouseleave', () => hideLinkTooltip());
        linkLocalPdfsInfoIcon.addEventListener('click', (e) => { e.stopPropagation(); linkTooltipVisible ? hideLinkTooltip(true) : showLinkTooltip(); });
        // document 点击事件来关闭它，应与templateTooltip的逻辑分开或整合
    }
    // 新增：滚动翻页
    const pdfViewColumnForScroll = document.getElementById('pdfViewColumn');
    let lastScrollTime = 0; // 用于函数节流，防止滚动过快
    const SCROLL_DEBOUNCE_TIME = 200; // 滚动事件的节流间隔（毫秒），可调整

    if (pdfViewColumnForScroll) {
        pdfViewColumnForScroll.addEventListener('wheel', (event) => {
            // 1. 检查PDF是否已加载且当前没有页面正在渲染
            if (!pdfDoc || pageRendering) {
                return; // 如果没有PDF或正在渲染，则不执行任何操作
            }

            // 2. 简单的函数节流：确保两次有效滚动之间有足够的时间间隔
            const currentTime = Date.now();
            if (currentTime - lastScrollTime < SCROLL_DEBOUNCE_TIME) {
                // event.preventDefault(); // 即使节流，也可能需要阻止默认行为，以防累积滚动
                return;
            }
            lastScrollTime = currentTime;

            // 3. 阻止默认的滚轮行为（例如，防止整个页面或模态框滚动）
            event.preventDefault();

            // 4. 根据滚轮方向判断是上一页还是下一页
            if (event.deltaY > 0) {
                // deltaY > 0 表示向下滚动 (或在某些触控板上是“向前”内容)
                console.log("Scroll down detected - next page");
                onNextPage();
            } else if (event.deltaY < 0) {
                // deltaY < 0 表示向上滚动 (或在某些触控板上是“向后”内容)
                console.log("Scroll up detected - prev page");
                onPrevPage();
            }
        }, { passive: false }); // passive: false 很重要，因为我们调用了 event.preventDefault()
    }

    // --- 核心功能函数定义 ---
    // 在 DOMContentLoaded 内部

    function saveTableDataToLocalStorage() { /* ... (保持不变) ... */ if (tableData && tableData.length >= 0) { try { const dataToSave = JSON.stringify(tableData); localStorage.setItem(LOCAL_STORAGE_KEY_TABLE_DATA, dataToSave); console.log('[LocalStorage] Saved tableData. Items:', tableData.length); } catch (error) { console.error('[LocalStorage] Error saving tableData:', error); showStatus('保存文献列表到本地失败！', 'text-red-500'); } } }
    function loadTableDataFromLocalStorage() { /* ... (保持不变) ... */ try { const savedData = localStorage.getItem(LOCAL_STORAGE_KEY_TABLE_DATA); if (savedData) { const parsedData = JSON.parse(savedData); if (Array.isArray(parsedData)) { tableData = parsedData; console.log('[LocalStorage] Loaded tableData. Items:', tableData.length); if (tableData.length > 0) { showStatus(`已恢复上次列表 (${tableData.length} 条)。`, 'text-green-500', 3000); } return true; } } } catch (error) { console.error('[LocalStorage] Error loading tableData:', error); showStatus('加载本地列表失败！数据可能已损坏。', 'text-red-500'); localStorage.removeItem(LOCAL_STORAGE_KEY_TABLE_DATA); } return false; }
    function handleFile(file) { /* ... (保持不变) ... */ showStatus('正在处理文件...', 'text-blue-500'); if(resultsSection) resultsSection.classList.add('hidden'); if(batchActionsSection) batchActionsSection.classList.add('hidden'); if(resultsTableBody) resultsTableBody.innerHTML = ''; if(noResultsMessage) noResultsMessage.classList.add('hidden'); tableData = []; displayedTableData = []; const fileName = file.name.toLowerCase(); const reader = new FileReader(); if (fileName.endsWith('.csv')) { Papa.parse(file, { header: true, skipEmptyLines: true, complete: (results) => parseComplete(results.data, results.meta.fields, [], 'CSV'), error: (error) => parseError(error, 'CSV') }); } else if (fileName.endsWith('.xls') || fileName.endsWith('.xlsx')) { reader.onload = (e) => { try { const data = e.target.result; const workbook = XLSX.read(data, { type: 'binary' }); const firstSheetName = workbook.SheetNames[0]; const worksheet = workbook.Sheets[firstSheetName]; const jsonData = XLSX.utils.sheet_to_json(worksheet, { defval: "" }); const headers = jsonData.length > 0 ? Object.keys(jsonData[0]) : []; parseComplete(jsonData, headers, [], 'Excel'); } catch (error) { parseError(error, 'Excel'); } }; reader.onerror = (error) => parseError(error, 'FileReader (Excel)'); reader.readAsBinaryString(file); } else { showStatus('不支持的文件类型。请上传CSV, XLS, 或 XLSX 文件。', 'text-red-500'); } }
    function parseComplete(data, headers, errors, type) { /* ... (保持不变, 确保调用 applyFiltersAndSort) ... */ if (errors && errors.length > 0) { console.error(`${type} Parsing Errors:`, errors); showStatus(`解析${type}文件出错: ${errors[0].message}.`, 'text-red-500'); return; } if (!data || data.length === 0) { showStatus(`${type}文件为空或无数据。`, 'text-yellow-500'); tableData = []; displayedTableData = []; applyFiltersAndSort(); return; } tableData = data.map((row, index) => ({ ...row, _id: `row-${Date.now()}-${index}`, pdfLink: '', status: '待处理' })); currentStatusFilter = 'all'; if(statusFilterSelect) statusFilterSelect.value = 'all'; currentSortColumn = null; currentSortDirection = 'asc'; applyFiltersAndSort(); showStatus(`成功处理 ${tableData.length} 条记录。`, 'text-green-500'); saveTableDataToLocalStorage(); }


    function displayScreenshotsForCurrentArticle() {
    // 首先，从DOM中获取需要操作的元素
    // 这些元素应该在 DOMContentLoaded 的顶部已经被 const 声明并赋值了
    // 例如: const screenshotsListContainer = document.getElementById('screenshotsListContainer');
    //       const noScreenshotsMessage = document.getElementById('noScreenshotsMessage');
    //       const currentArticleScreenshotsDiv = document.getElementById('currentArticleScreenshots');
    // 为了函数健壮性，我们在函数内部再次确认一下（或者依赖于它们是有效的全局变量）

        const screenshotsListContainerEl = document.getElementById('screenshotsListContainer');
        const noScreenshotsMessageEl = document.getElementById('noScreenshotsMessage');
        const currentArticleScreenshotsDivEl = document.getElementById('currentArticleScreenshots');

        console.log("[DisplaySS] Called. CurrentViewingArticleRowId:", currentViewingArticleRowId);
    // 调试日志，确认DOM元素是否正确获取
    // console.log("[DisplaySS] screenshotsListContainerEl:", screenshotsListContainerEl);
    // console.log("[DisplaySS] noScreenshotsMessageEl:", noScreenshotsMessageEl);
    // console.log("[DisplaySS] currentArticleScreenshotsDivEl:", currentArticleScreenshotsDivEl);

        if (!currentViewingArticleRowId || !screenshotsListContainerEl || !noScreenshotsMessageEl || !currentArticleScreenshotsDivEl) {
            console.warn("[DisplaySS] Aborting: Missing critical elements (screenshotsListContainer, noScreenshotsMessage, currentArticleScreenshotsDiv) or currentViewingArticleRowId is not set.");
            if (screenshotsListContainerEl) screenshotsListContainerEl.innerHTML = ''; // 清空以防万一
            if (noScreenshotsMessageEl) noScreenshotsMessageEl.classList.remove('hidden'); // 显示“无截图”消息
            return;
        }

        const article = tableData.find(row => row._id === currentViewingArticleRowId);
    // console.log("[DisplaySS] Found article in tableData:", article);

        screenshotsListContainerEl.innerHTML = ''; // 清空上一次显示的截图列表

        if (article && article.screenshots && article.screenshots.length > 0) {
            console.log(`[DisplaySS] Article '${article._id}' has ${article.screenshots.length} screenshots.`);
            noScreenshotsMessageEl.classList.add('hidden'); // 隐藏“无截图”消息

            const ul = document.createElement('ul');
            ul.className = 'list-none space-y-1 text-gray-700 text-xs'; // 改为 list-none，因为我们会自定义每项的布局

            article.screenshots.forEach((ss, index) => {
                const li = document.createElement('li');
                // 使用flex布局让文本和按钮在同一行
                li.className = 'hover:bg-gray-200 p-2 rounded transition-colors duration-150 flex justify-between items-center';
                li.dataset.screenshotId = ss.id;
                li.dataset.articleId = article._id;
                if (ss.thumbnailDataUrl) {
                    console.log(`[DisplaySS] Screenshot ID ${ss.id} HAS thumbnailDataUrl, starts with:`, ss.thumbnailDataUrl.substring(0, 50));
                    const imgContainer = document.createElement('div'); // 创建一个容器来控制图片大小和边距
                    imgContainer.className = 'flex-shrink-0 mr-2'; // 防止图片被压缩，并添加右边距
                    const img = document.createElement('img');
                    img.src = ss.thumbnailDataUrl;
                    img.alt = `截图 ${index + 1} (页 ${ss.pageNumber})`;
                    img.className = 'w-24 h-auto border border-gray-300 rounded shadow-sm'; // 例如 w-24 (96px)
            // img.style.maxWidth = '100px'; // 或者用 style 直接控制
            // img.style.maxHeight = '80px';
                    imgContainer.appendChild(img);
                    li.appendChild(imgContainer); // 将图片容器添加到列表项
                } else {
                    console.log(`[DisplaySS] Screenshot ID ${ss.id} does NOT have thumbnailDataUrl.`);
            // 可以选择添加一个占位符或者什么都不做
                    const placeholder = document.createElement('div');
                    placeholder.className = 'w-24 h-16 border border-dashed border-gray-300 rounded mr-2 flex items-center justify-center text-gray-400 text-xs';
                    placeholder.textContent = '无预览';
                    li.appendChild(placeholder);
                }

         // 2. 显示文本信息和控制按钮
                const textAndControlsContainer = document.createElement('div');
                textAndControlsContainer.className = 'flex-grow flex flex-col'; // 让文本和按钮垂直排列并占据剩余空间

                const textInfo = document.createElement('div');
                textInfo.className = 'cursor-pointer mb-1'; // 文本区域可点击，底部一点间距
                let displayText = `页 ${ss.pageNumber} - "${truncateText(ss.filenameSuggested, 25)}"`;
                if (ss.chartType && ss.chartType !== "未指定") {
                    displayText += ` <span class="text-xs px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded-full">${ss.chartType}</span>`; // 类型用小标签显示
                }
                // --- 新增同步状态提示 ---
                if (ss.serverFilePath) { // 如果有服务器路径，说明已同步
                    displayText += ` <i class="fas fa-cloud-upload-alt text-green-500 ml-2" title="已同步到服务器: ${ss.serverFilePath}"></i>`;
                } else if (ss.syncStatus === 'failed') { // 假设未来有同步失败状态
                    displayText += ` <i class="fas fa-exclamation-circle text-red-500 ml-2" title="同步失败"></i>`;
                }
                // --- MODIFIED_START: Add WPD data icon ---
                if (ss.wpdData && ss.wpdData.trim() !== '') {
                    displayText += ` <i class="fas fa-ruler-combined text-purple-500 ml-2" title="已提取WPD数据"></i>`;
                }
                // --- MODIFIED_END: Add WPD data icon ---




                textInfo.innerHTML = displayText; // 使用innerHTML以允许span标签生效

                textInfo.addEventListener('click', function() {
                    handleScreenshotItemClick(article._id, ss.id);
                });
                textAndControlsContainer.appendChild(textInfo);

                if (ss.description) {
                    const descP = document.createElement('p');
                    descP.className = 'text-xs text-gray-500';
                    descP.textContent = truncateText(ss.description, 40);
                    textAndControlsContainer.appendChild(descP);
                }

        // 删除按钮 (或其他控制按钮)
                const controlsDiv = document.createElement('div');
                controlsDiv.className = 'mt-1 flex items-center space-x-2';; // 与描述有点间距

                if (ss.serverFilePath) { // 只为已同步到服务器的截图显示此按钮
                      const downloadForWpdButton = document.createElement('button');
                      downloadForWpdButton.innerHTML = `<i class="fas fa-draw-polygon mr-1 text-blue-500"></i> <span class="text-xs text-blue-500 hover:text-blue-700">用WPD提取</span>`;
                      downloadForWpdButton.className = 'p-1 rounded hover:bg-blue-100';
                      downloadForWpdButton.title = `下载原图 (${ss.serverFilePath.split('/').pop()}) 并准备用于WebPlotDigitizer`;

                      downloadForWpdButton.onclick = (event) => {
                          event.stopPropagation(); // 防止触发 li 的点击事件 (如果li有的话)

                          const backendApiUrlInputElem = document.getElementById('backendApiUrlInput');
                          if (!backendApiUrlInputElem || !backendApiUrlInputElem.value) {
                             showStatus('错误：后端API链接未配置，无法下载原图。', 'text-red-500', 4000);
                             return;
                          }
                           const baseApiUrl = backendApiUrlInputElem.value.trim().replace(/\/$/, "");
                           const downloadUrl = `${baseApiUrl}/api/download_screenshot_image?path=${encodeURIComponent(ss.serverFilePath)}`;

                           console.log(`[WPD_Download] Attempting to download original image from: ${downloadUrl}`);
                           showStatus(`正在准备下载原图: ${ss.serverFilePath.split('/').pop()}...`, 'text-blue-500', 3000);

            // 使用创建临时链接的方式触发下载，这种方式更可靠
                           const tempLink = document.createElement('a');
                           tempLink.href = downloadUrl;

            // 浏览器可能无法直接从 serverFilePath 推断文件名，最好后端API设置 Content-Disposition
            // 但前端也可以尝试设置 download 属性，虽然对于跨域的 Content-Disposition 可能不起作用
            // tempLink.download = ss.serverFilePath.split('/').pop(); // 尝试建议文件名

                          document.body.appendChild(tempLink);
                          tempLink.click();
                          document.body.removeChild(tempLink);

            // 可以在这里给用户更明确的下一步指示
                          setTimeout(() => { // 延迟一点提示，确保下载已开始
                               showStatus(`原图已开始下载。请打开 WebPlotDigitizer 并上传此文件进行数据提取。 <a href="https://automeris.io/WebPlotDigitizer/" target="_blank" class="text-blue-600 hover:underline">打开WebPlotDigitizer</a>`, 'text-green-500', 10000);
                          }, 1000);
                      };
                      controlsDiv.appendChild(downloadForWpdButton);
                }




                const deleteButton = document.createElement('button');
                deleteButton.innerHTML = `<i class="fas fa-trash-alt text-red-500 hover:text-red-700"></i> <span class="text-xs text-red-500 hover:text-red-700">删除</span>`;
                deleteButton.className = 'p-1 rounded hover:bg-red-100';
                deleteButton.title = "删除此截图记录";
                deleteButton.onclick = (event) => {
                    event.stopPropagation();
                    handleDeleteScreenshot(article._id, ss.id);
                };
                controlsDiv.appendChild(deleteButton);
                textAndControlsContainer.appendChild(controlsDiv);

                li.appendChild(textAndControlsContainer);
                ul.appendChild(li);
            });
            screenshotsListContainerEl.appendChild(ul);
            currentArticleScreenshotsDivEl.classList.remove('hidden');

                // 1. 显示缩略图 (如果存在)

        } else {
            console.log("[DisplaySS] No screenshots found for this article, or article/screenshots array is missing/empty.");
            noScreenshotsMessage.classList.remove('hidden'); // 显示“无截图”消息
            currentArticleScreenshotsDiv.classList.remove('hidden'); // 即使没截图，"尚未..."的消息也应在容器里显示
        }
    }

    function handleScreenshotItemClick(articleId, screenshotId) {
        console.log(`[ScreenshotClick] Editing screenshot. Article ID: ${articleId}, Screenshot ID: ${screenshotId}`);

        const article = tableData.find(row => row._id === articleId);
        if (article && article.screenshots) {
            const screenshot = article.screenshots.find(ss => ss.id === screenshotId);
            if (screenshot) {
                console.log("[ScreenshotClick] Found screenshot details for editing:", screenshot);

                // 填充模态框的显示信息 (只读)
                if(editSsArticleIdSpan) editSsArticleIdSpan.textContent = articleId;
                if(editSsIdSpan) editSsIdSpan.textContent = screenshotId;
                if(editSsFilenameSpan) editSsFilenameSpan.textContent = screenshot.filenameSuggested || 'N/A';

                // 填充表单的当前值
                if(editSsChartTypeSelect) editSsChartTypeSelect.value = screenshot.chartType || "未指定";
                if(editSsDescriptionTextarea) editSsDescriptionTextarea.value = screenshot.description || "";
                // --- MODIFIED_START: Pre-fill WPD textarea ---
                const wpdTextarea = document.getElementById('editSsWpdDataTextarea');
                if(wpdTextarea) {
                    wpdTextarea.value = screenshot.wpdData || "";
                }
                // --- MODIFIED_END: Pre-fill WPD textarea ---


                // 将当前编辑的 articleId 和 screenshotId 存到隐藏input中，供保存按钮使用
                if(editingScreenshotArticleIdInput) editingScreenshotArticleIdInput.value = articleId;
                if(editingScreenshotIdInput) editingScreenshotIdInput.value = screenshotId;

                // 更新模态框标题 (可选)
                if(editScreenshotModalTitle) editScreenshotModalTitle.textContent = `编辑截图 (页 ${screenshot.pageNumber} - ${truncateText(screenshot.filenameSuggested, 20)})`;


                if (editScreenshotModal) editScreenshotModal.style.display = 'block'; // 显示编辑模态框

            } else {
                console.error(`[ScreenshotClick] Screenshot with ID ${screenshotId} not found in article ${articleId}.`);
                alert("错误：未找到要编辑的截图记录。");
            }
        } else {
            console.error(`[ScreenshotClick] Article with ID ${articleId} not found or has no screenshots.`);
            alert("错误：未找到对应的文献记录或该文献没有截图。");
        }
    }
    function handleDeleteScreenshot(articleId, screenshotId) {
        console.log(`[DeleteSS] Request to delete screenshot. Article ID: ${articleId}, Screenshot ID: ${screenshotId}`);

        const articleIndex = tableData.findIndex(row => row._id === articleId);
        if (articleIndex > -1 && tableData[articleIndex].screenshots) {
            const screenshotIndex = tableData[articleIndex].screenshots.findIndex(ss => ss.id === screenshotId);
            if (screenshotIndex > -1) {
                const screenshotToDelete = tableData[articleIndex].screenshots[screenshotIndex];

                if (confirm(`您确定要删除截图 "${truncateText(screenshotToDelete.filenameSuggested, 30)}" (页 ${screenshotToDelete.pageNumber}) 吗？此操作不可恢复。`)) {
                    // 从数组中移除截图记录
                    tableData[articleIndex].screenshots.splice(screenshotIndex, 1);

                    saveTableDataToLocalStorage();         // 保存更改到 localStorage
                    displayScreenshotsForCurrentArticle(); // 刷新截图列表以显示更新

                    showStatus(`截图 "${truncateText(screenshotToDelete.filenameSuggested, 20)}" 已删除。`, "text-green-500", 3000);
                    console.log(`[DeleteSS] Screenshot ${screenshotId} deleted from article ${articleId}.`);
                } else {
                    showStatus('删除操作已取消。', 'text-gray-500', 2000);
                }
            } else {
                console.error(`[DeleteSS] Screenshot with ID ${screenshotId} not found in article ${articleId} for deletion.`);
                alert("错误：未找到要删除的截图记录。");
            }
        } else {
            console.error(`[DeleteSS] Article with ID ${articleId} not found for deleting screenshot.`);
            alert("错误：未找到对应的文献记录。");
        }
    }

    function parseError(error, type) { /* ... (保持不变) ... */ console.error(`${type} Error:`, error); showStatus(`读取${type}文件失败: ${error.message || '未知错误'}.`, 'text-red-500'); }

    function applyFiltersAndSort() { /* ... (保持不变, 使用全局 tableData, currentStatusFilter, currentSortColumn, currentSortDirection) ... */ if (!tableData) { displayedTableData = []; } else { let processedData = [...tableData]; if (currentStatusFilter && currentStatusFilter !== 'all') { processedData = processedData.filter(row => row.status === currentStatusFilter); } if (currentSortColumn) { const sampleRowForHeaders = tableData.length > 0 ? tableData[0] : (processedData.length > 0 ? processedData[0] : null); let sortHeaderKey = null; if (sampleRowForHeaders) { sortHeaderKey = findHeader(Object.keys(sampleRowForHeaders), COLUMN_MAPPING[currentSortColumn] || [currentSortColumn]); } if (sortHeaderKey) { processedData.sort((a, b) => { let valA = a[sortHeaderKey]; let valB = b[sortHeaderKey]; if (currentSortColumn === 'year') { let numA = parseInt(valA, 10); let numB = parseInt(valB, 10); const aIsNaN = isNaN(numA); const bIsNaN = isNaN(numB); if (aIsNaN && bIsNaN) return 0; if (aIsNaN) return currentSortDirection === 'asc' ? 1 : -1; if (bIsNaN) return currentSortDirection === 'asc' ? -1 : 1; return currentSortDirection === 'asc' ? numA - numB : numB - numA; } else if (currentSortColumn === 'title') { valA = String(valA || '').toLowerCase(); valB = String(valB || '').toLowerCase(); return currentSortDirection === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA); } return 0; }); } } displayedTableData = processedData; } let headersForDisplay = []; if (tableData && tableData.length > 0 && tableData[0]) { headersForDisplay = Object.keys(tableData[0]).filter(key => !['_id', 'pdfLink', 'status'].includes(key)); } displayResults(displayedTableData, headersForDisplay); }
    function displayResults(dataToDisplay, originalHeaders) { /* ... (保持不变, 使用明确的appendChild创建所有td) ... */ if(resultsSection) resultsSection.classList.remove('hidden'); if(resultsTableBody) resultsTableBody.innerHTML = ''; if(noResultsMessage) noResultsMessage.classList.add('hidden'); const actualHeaders = { title: findHeader(originalHeaders, COLUMN_MAPPING.title), authors: findHeader(originalHeaders, COLUMN_MAPPING.authors), year: findHeader(originalHeaders, COLUMN_MAPPING.year), source: findHeader(originalHeaders, COLUMN_MAPPING.source), doi: findHeader(originalHeaders, COLUMN_MAPPING.doi) }; const tableHeaders = document.querySelectorAll('#mainResultsTable thead th'); tableHeaders.forEach(th => { const columnKey = th.dataset.columnKey; const existingArrow = th.querySelector('.sort-arrow'); if (existingArrow) existingArrow.remove(); if (columnKey && (COLUMN_MAPPING[columnKey] || columnKey === 'year' || columnKey === 'title')) { th.classList.add('sortable-header'); if (!th.getAttribute('data-sort-listener-added')) { th.addEventListener('click', () => handleSort(columnKey)); th.setAttribute('data-sort-listener-added', 'true'); } if (currentSortColumn === columnKey) { const arrow = document.createElement('span'); arrow.className = 'sort-arrow ml-1'; arrow.innerHTML = currentSortDirection === 'asc' ? '▲' : '▼'; th.appendChild(arrow); } } else { th.classList.remove('sortable-header'); } }); const doiColumnExists = actualHeaders.doi !== null; if (!doiColumnExists && tableData.length > 0) { const errorMsg = '错误：文件中未找到DOI列。'; showStatus(errorMsg, 'text-red-500 font-bold'); if(noResultsMessage) { noResultsMessage.textContent = errorMsg + ' 确保DOI列名匹配: ' + COLUMN_MAPPING.doi.join(', '); noResultsMessage.classList.remove('hidden'); } if(batchActionsSection) batchActionsSection.classList.add('hidden'); if(resultsSection) resultsSection.classList.remove('hidden'); return; } if (dataToDisplay.length === 0) { if(noResultsMessage) { noResultsMessage.textContent = tableData.length === 0 ? '无数据或文件为空。' : '无符合筛选条件的文献。'; noResultsMessage.classList.remove('hidden'); } } if (doiColumnExists && tableData.length > 0) { if(batchActionsSection) batchActionsSection.classList.remove('hidden'); } else { if(batchActionsSection) batchActionsSection.classList.add('hidden'); } dataToDisplay.forEach((rowData) => { const tr = document.createElement('tr'); tr.className = 'hover:bg-gray-50 transition'; tr.dataset.id = rowData._id; const title = String(rowData[actualHeaders.title] || 'N/A'); const authors = String(rowData[actualHeaders.authors] || 'N/A'); const year = String(rowData[actualHeaders.year] || 'N/A'); const sourceVal = String(rowData[actualHeaders.source] || 'N/A'); const doiValue = actualHeaders.doi && rowData[actualHeaders.doi] ? String(rowData[actualHeaders.doi]).trim() : null; const currentPdfLink = rowData.pdfLink || ''; const currentStatus = rowData.status; const cellsInfo = [ { content: truncateText(title, 60), classes: 'px-2 py-1 text-sm text-gray-700 ws-normal break-words' }, { content: truncateText(authors, 40), classes: 'px-2 py-1 text-sm text-gray-700 ws-normal break-words' }, { content: year, classes: 'px-1 py-1 text-sm text-gray-500' }, { content: truncateText(sourceVal, 50), classes: 'px-2 py-1 text-sm text-gray-500 ws-normal break-words' }, { content: doiValue || '无', classes: 'px-2 py-1 text-sm text-gray-500 font-mono break-all' }]; cellsInfo.forEach(cell => { const td = document.createElement('td'); td.className = cell.classes; td.textContent = cell.content; tr.appendChild(td); }); const pdfLinkCell = document.createElement('td'); pdfLinkCell.className = 'px-2 py-1 text-sm text-gray-700'; const pdfLinkInput = document.createElement('input'); pdfLinkInput.type = 'url'; pdfLinkInput.className = 'pdf-link-input'; pdfLinkInput.placeholder = '粘贴PDF链接...'; pdfLinkInput.value = currentPdfLink; pdfLinkInput.addEventListener('change', (e) => { updateTableData(rowData._id, 'pdfLink', e.target.value); }); pdfLinkCell.appendChild(pdfLinkInput); tr.appendChild(pdfLinkCell); const statusCell = document.createElement('td'); statusCell.className = 'px-2 py-1 text-sm text-gray-500'; const statusSelect = document.createElement('select'); statusSelect.className = 'status-select'; ['待处理', '已搜索', '自动查找中...', '链接已找到', '链接已找到 (自动)', '链接无效', '未找到', '自动查找失败', '下载成功', '打开/下载尝试', '打开/下载失败'].forEach(s => { const option = document.createElement('option'); option.value = s; option.textContent = s; if (s === currentStatus) option.selected = true; statusSelect.appendChild(option); }); statusSelect.addEventListener('change', (e) => { updateTableData(rowData._id, 'status', e.target.value); }); statusCell.appendChild(statusSelect); tr.appendChild(statusCell); const actionCell = document.createElement('td'); actionCell.className = 'px-2 py-1 text-sm text-gray-500 whitespace-nowrap'; tr.appendChild(actionCell); updateActionButtonsForRow(tr, doiValue, currentPdfLink, currentStatus); if(resultsTableBody) resultsTableBody.appendChild(tr); }); const mainTable = document.getElementById('mainResultsTable'); if (mainTable && typeof makeTableResizable === 'function') { makeTableResizable(mainTable); } }
    function handleSort(columnKey) { /* ... (不变) ... */ if (currentSortColumn === columnKey) { currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc'; } else { currentSortColumn = columnKey; currentSortDirection = 'asc'; } applyFiltersAndSort(); }
    function updateTableData(rowId, field, value) { /* ... (不变, 确保调用 applyFiltersAndSort) ... */ const rowIndex = tableData.findIndex(row => row._id === rowId); let dataWasModified = false; let needsFullRefresh = false; if (rowIndex > -1) { if (tableData[rowIndex][field] !== value) { tableData[rowIndex][field] = value; dataWasModified = true; } if (field === 'pdfLink') { if (value && value.trim() !== '') { if (['待处理', '已搜索', '链接无效', '未找到', '自动查找失败'].includes(tableData[rowIndex].status)) { const newStatus = (tableData[rowIndex].status === '自动查找中...' || tableData[rowIndex].status.startsWith('链接已找到 (自动)')) ? '链接已找到 (自动)' : '链接已找到'; if (tableData[rowIndex].status !== newStatus) { tableData[rowIndex].status = newStatus; dataWasModified = true; } } } else { if (tableData[rowIndex].status.startsWith('链接已找到')) { if (tableData[rowIndex].status !== '链接无效') { tableData[rowIndex].status = '链接无效'; dataWasModified = true; } } } needsFullRefresh = true; } else if (field === 'status') { needsFullRefresh = true; } if (dataWasModified) { saveTableDataToLocalStorage(); needsFullRefresh = true; } if (needsFullRefresh) { applyFiltersAndSort(); } } }
    function updateActionButtonsForRow(trElement, doi, pdfLink, currentStatus) {
        /* ... (不变, 包含所有按钮逻辑) ... */ const actionCell = trElement.querySelector('td:last-child');
        if (!actionCell) return; actionCell.innerHTML = '';
        const rowId = trElement.dataset.id;
        const rowData = tableData.find(r => r._id === rowId); if (!rowData) return;
        const titleHeader = findHeader(Object.keys(rowData), COLUMN_MAPPING.title);
        const currentTitle = rowData[titleHeader] ? String(rowData[titleHeader]).trim() : null;
        const sourceHeader = findHeader(Object.keys(rowData), COLUMN_MAPPING.source);
        const currentJournal = rowData[sourceHeader] ? String(rowData[sourceHeader]).trim() : null;
        if (doi) { const btn = document.createElement('button');
            btn.innerHTML = `<i class="fas fa-search mr-1"></i> Sci-Hub`;
            btn.className = 'action-button bg-blue-500 hover:bg-blue-600 text-white text-xs py-1 px-2 rounded-md shadow';
            btn.title = "Sci-Hub查找";
            btn.onclick = () => { let url = sciHubDomainSelect.value;
                if (url==='custom') url=customSciHubUrlInput.value.trim();
                if(!url) {alert('请输入Sci-Hub链接');
                    return;}
                if(!url.startsWith('http')) url='https://'+url;
                if(!url.endsWith('/')) url+='/';
                window.open(url+encodeURIComponent(doi),'_blank');
                updateTableData(rowId,'status','已搜索');}; actionCell.appendChild(btn); } if (currentTitle) { const btn=document.createElement('button'); btn.innerHTML=`<i class="fas fa-archive mr-1"></i> arXiv`; btn.className='action-button bg-green-700 hover:bg-green-800 text-white text-xs py-1 px-2 rounded-md shadow'; btn.title="arXiv标题搜索"; btn.onclick=()=>{window.open(`https://arxiv.org/search/?searchtype=title&query=${encodeURIComponent(currentTitle)}`,'_blank');}; actionCell.appendChild(btn);} if (doi || currentTitle) { const btn=document.createElement('button'); btn.innerHTML=`<i class="fas fa-flask mr-1"></i> WoS (CN)`; btn.className='action-button bg-purple-500 hover:bg-purple-600 text-white text-xs py-1 px-2 rounded-md shadow'; btn.title="Web of Science搜索"; btn.onclick=()=>{let url=''; const base='https://webofscience.clarivate.cn'; if(doi){url=`${base}/wos/alldb/basic-search;search_mode=BasicSearch;action=search;value=${encodeURIComponent(doi)};option=DOI`;}else if(currentTitle&&currentJournal){url=`${base}/wos/alldb/advanced-search;search_mode=AdvancedSearch;action=search;query=TI%3D(${encodeURIComponent(currentTitle)})%20AND%20SO%3D(${encodeURIComponent(currentJournal)})`;}else if(currentTitle){url=`${base}/wos/alldb/basic-search;search_mode=BasicSearch;action=search;value=${encodeURIComponent(currentTitle)};option=Title`;} if(url)window.open(url,'_blank'); else alert('无足够信息在WoS中搜索。');}; actionCell.appendChild(btn);} if (currentTitle) { const btn=document.createElement('button'); btn.innerHTML=`<i class="fas fa-atom mr-1"></i> X-MOL`; btn.className='action-button bg-orange-500 hover:bg-orange-600 text-white text-xs py-1 px-2 rounded-md shadow'; btn.title="X-MOL标题搜索"; btn.onclick=()=>{window.open(`https://www.x-mol.com/paper/search/q?option=${encodeURIComponent(currentTitle)}`,'_blank');}; actionCell.appendChild(btn);} if (currentTitle) { const btn=document.createElement('button'); btn.innerHTML=`<i class="fas fa-book-reader mr-1"></i> ScienceDirect`; btn.className='action-button bg-red-500 hover:bg-red-600 text-white text-xs py-1 px-2 rounded-md shadow'; btn.title="ScienceDirect标题搜索"; btn.onclick=()=>{window.open(`https://www.sciencedirect.com/search?qs=${encodeURIComponent(currentTitle)}`,'_blank');}; actionCell.appendChild(btn);} const viewPdfBtn = document.createElement('button'); viewPdfBtn.innerHTML = `<i class="fas fa-file-pdf mr-1"></i> 查看/处理PDF`;
        viewPdfBtn.className = 'action-button bg-indigo-500 hover:bg-indigo-600 text-white text-xs py-1 px-2 rounded-md shadow';
        viewPdfBtn.title="打开PDF查看器";
        viewPdfBtn.onclick = () => {
            currentViewingArticleRowId = rowId;
            const rowDataForViewer = tableData.find(r => r._id === rowId); // 从最新的tableData获取
            let articleTitleForViewer = `PDF 查看器 (条目ID: ${rowId.slice(-5)})`;
            if (rowDataForViewer) {
                const titleH = findHeader(Object.keys(rowDataForViewer), COLUMN_MAPPING.title);
                const actualTitle = rowDataForViewer[titleH] ? String(rowDataForViewer[titleH]).trim() : null;
                if (actualTitle) articleTitleForViewer = truncateText(actualTitle, 50);
            }
            if(pdfViewerTitle) pdfViewerTitle.textContent = articleTitleForViewer;

            if (pdfDoc) closeModal('pdfViewerModal'); // 清理上一个

            // ***** 核心修改：优先使用已关联的本地PDF *****
            if (rowDataForViewer && rowDataForViewer.localPdfFileObject) {
                console.log(`[ViewPDFButton] Found linked local PDF for row ${rowId}. Loading directly into PDF.js...`);
                showStatus('正在加载已关联的本地PDF...', 'text-blue-500');
                // 直接调用 handlePdfFileSelected，但传入的是 File 对象而不是事件
                // 我们需要稍微改造一下 handlePdfFileSelected 或创建一个新函数来处理File对象
                loadPdfFileObjectIntoViewer(rowDataForViewer.localPdfFileObject); // <--- 调用新函数
                if (pdfViewerModal) pdfViewerModal.style.display = 'block';
            }
            // ***** 再尝试使用rowData.pdfLink (如果是可直接加载的URL) *****
            else if (rowDataForViewer && rowDataForViewer.pdfLink ) {
                 // 这里的 "谱图浏览器可直接加载的URL类型判断" 需要具体实现
                 // 例如，检查是否是 arXiv.org/pdf/ 链接，或者是否以 .pdf 结尾且CORS友好
                 // pdfjsLib.getDocument(rowDataForViewer.pdfLink).promise.then(...)
                 // 这个逻辑我们之前讨论过，暂时先跳过，优先本地文件和手动选择
                 // 为简化，如果上面没匹配到本地文件，就走手动选择流程
                 if (pdfViewerModal) pdfViewerModal.style.display = 'block';
                 showStatus('请在PDF查看器中点击“打开PDF”按钮选择本地文件，或提供可直接访问的PDF链接。', 'text-blue-500', 4000);
            }
            // ***** 最后，如果都没有，才提示用户手动选择 *****
            else {
                if (pdfViewerModal) pdfViewerModal.style.display = 'block';
                showStatus('请在PDF查看器中点击“打开PDF”按钮选择本地文件。', 'text-blue-500', 4000);
            }
        };
        actionCell.appendChild(viewPdfBtn);
        if (doi || currentTitle) { const btn=document.createElement('button');
            btn.innerHTML=`<i class="fas fa-robot mr-1"></i> 自动查找`; btn.className='action-button bg-teal-500 hover:bg-teal-600 text-white text-xs py-1 px-2 rounded-md shadow'; btn.title="后端自动查找PDF链接"; btn.disabled = currentStatus === '自动查找中...'; btn.onclick=()=>{handleAutoFindPdfLink(doi, rowId);}; actionCell.appendChild(btn); } if (pdfLink && pdfLink.trim() !== '') { const dlBtn=document.createElement('button'); dlBtn.innerHTML=`<i class="fas fa-file-arrow-down mr-1"></i> 下载PDF`; dlBtn.className='action-button bg-green-500 hover:bg-green-600 text-white text-xs py-1 px-2 rounded-md shadow'; dlBtn.title="下载此PDF"; dlBtn.onclick=()=>{const doiH=findHeader(Object.keys(rowData),COLUMN_MAPPING.doi);const filenamePrefix=currentTitle||(rowData[doiH]||'document'); downloadSinglePdf(pdfLink,filenamePrefix,rowId);}; actionCell.appendChild(dlBtn); const openBtn=document.createElement('button'); openBtn.innerHTML=`<i class="fas fa-external-link-alt mr-1"></i> 打开链接`; openBtn.className='action-button bg-gray-400 hover:bg-gray-500 text-white text-xs py-1 px-2 rounded-md shadow'; openBtn.title="打开PDF链接"; openBtn.onclick=()=>{window.open(pdfLink,'_blank');}; actionCell.appendChild(openBtn);} if (actionCell.children.length === 0) actionCell.innerHTML = `<span class="text-xs text-gray-400">无操作</span>`; }
    function makeTableResizable(tableElement) { /* ... (不变) ... */ if (!tableElement) return; const headers = Array.from(tableElement.querySelectorAll('thead th')); let currentlyResizingHeader = null; let startX; let startWidth; headers.forEach((header) => { let resizeHandle = header.querySelector('.resize-handle'); if (!resizeHandle) { resizeHandle = document.createElement('div'); resizeHandle.className = 'resize-handle'; header.appendChild(resizeHandle); } resizeHandle.addEventListener('mousedown', (e) => { e.preventDefault(); e.stopPropagation(); currentlyResizingHeader = header; startX = e.pageX; startWidth = currentlyResizingHeader.offsetWidth; document.documentElement.style.cursor = 'col-resize'; if(currentlyResizingHeader) currentlyResizingHeader.style.cursor = 'col-resize'; document.addEventListener('mousemove', onMouseMoveResizable); document.addEventListener('mouseup', onMouseUpResizable); }); }); function onMouseMoveResizable(e) { if (!currentlyResizingHeader) return; e.preventDefault(); const diffX = e.pageX - startX; let newWidth = startWidth + diffX; const minWidth = 50; if (newWidth < minWidth) newWidth = minWidth; currentlyResizingHeader.style.width = `${newWidth}px`; } function onMouseUpResizable(e) { if (!currentlyResizingHeader) return; e.preventDefault(); document.documentElement.style.cursor = ''; if(currentlyResizingHeader) currentlyResizingHeader.style.cursor = ''; document.removeEventListener('mousemove', onMouseMoveResizable); document.removeEventListener('mouseup', onMouseUpResizable); currentlyResizingHeader = null; } }
    function updateBatchProgress(current, total) { /* ... (不变) ... */ if (!batchProgressContainer || !batchProgressBar || !batchProgressText) return; if (total > 0 && current >= 0 && current <= total) { const percentage = (current / total) * 100; batchProgressBar.style.width = `${percentage}%`; batchProgressText.textContent = `已处理: ${current} / ${total}`; batchProgressContainer.classList.remove('hidden'); batchProgressText.classList.remove('hidden'); } else { batchProgressBar.style.width = '0%'; batchProgressText.textContent = ''; batchProgressContainer.classList.add('hidden'); batchProgressText.classList.add('hidden'); } }
    async function handleAutoFindPdfLink(doi, rowId) {
        /* ... (不变, 包含最新的日志和URL修正) ... */ console.log(`[HFAPL] Called with DOI: ${doi}, RowID: ${rowId}`);
        const backendUrl = backendApiUrlInput.value.trim();
        if (!backendUrl) { alert('请输入后端API链接。'); backendApiUrlInput.focus(); updateTableData(rowId, 'status', '自动查找失败'); return; } const rowData = tableData.find(r => r._id === rowId); if (!rowData) { console.error(`[HFAPL] RowData not found for ${rowId}`); updateTableData(rowId, 'status', '自动查找失败'); return; } const titleHeader = findHeader(Object.keys(rowData), COLUMN_MAPPING.title); const currentTitle = rowData[titleHeader] ? String(rowData[titleHeader]).trim() : null; if (!doi && !currentTitle) { console.error('[HFAPL] DOI and Title both missing for RowID:', rowId); updateTableData(rowId, 'status', '自动查找失败'); return; } console.log(`[HFAPL] Starting. DOI: ${doi||'N/A'}, Title: ${currentTitle||'N/A'}, Row: ${rowId}`); updateTableData(rowId, 'status', '自动查找中...'); const queryParams = new URLSearchParams(); if (doi) queryParams.append('doi', doi); if (currentTitle) queryParams.append('title', currentTitle); let baseApiUrl = backendUrl; if (baseApiUrl.includes('/api/find-pdf')) { baseApiUrl = baseApiUrl.substring(0, baseApiUrl.lastIndexOf('/api/')); } else if (baseApiUrl.endsWith('/')) { baseApiUrl = baseApiUrl.slice(0, -1); } const apiUrl = `${baseApiUrl}/api/find-pdf?${queryParams.toString()}`; try { const response = await fetch(apiUrl); console.log(`[HFAPL] Fetch response Row: ${rowId}, Status: ${response.status}, URL: ${apiUrl}`); const responseData = await response.json(); if (!response.ok) { throw new Error(responseData.error || responseData.message || `后端错误: ${response.status}`); } if (responseData.pdfLink) { console.log(`[HFAPL] PDF found Row ${rowId}: ${responseData.pdfLink}`); updateTableData(rowId, 'pdfLink', responseData.pdfLink); if (tableData.find(r => r._id === rowId).status !== '链接已找到 (自动)') { updateTableData(rowId, 'status', '链接已找到 (自动)'); } } else { console.log(`[HFAPL] PDF NOT found by backend Row ${rowId}. Message: ${responseData.message}`); updateTableData(rowId, 'status', '自动查找失败'); } } catch (error) { console.error('[HFAPL] Error Row:', rowId, error); updateTableData(rowId, 'status', '自动查找失败'); showStatus(`查找文献 (ID: ${rowId.slice(-5)}) 失败: ${error.message}`, 'text-red-500'); } }
    async function autoFindAllPdfs() { /* ... (不变, 包含最新的筛选逻辑和进度条调用) ... */ const backendUrl = backendApiUrlInput.value.trim(); if (!backendUrl) { alert('请输入后端API链接。'); backendApiUrlInput.focus(); return; } let itemsToSearchCount = 0; const promises = []; let completedCount = 0; console.log('[autoFindAllPdfs] Starting batch. Total items:', tableData.length); const itemsToProcess = tableData.filter((row) => { let doiValueFromRow = null; const doiHeaderName = findHeader(Object.keys(row), COLUMN_MAPPING.doi); if (doiHeaderName && row[doiHeaderName] != null) { doiValueFromRow = String(row[doiHeaderName]).trim(); if (doiValueFromRow === "") doiValueFromRow = null; } let currentTitleFromRow = null; const titleHeaderName = findHeader(Object.keys(row), COLUMN_MAPPING.title); if (titleHeaderName && row[titleHeaderName] != null) { currentTitleFromRow = String(row[titleHeaderName]).trim(); if (currentTitleFromRow === "") currentTitleFromRow = null; } return (doiValueFromRow || currentTitleFromRow) && (!row.pdfLink || row.pdfLink.trim() === '') && !['自动查找中...', '链接已找到', '链接已找到 (自动)', '下载成功', '自动查找失败'].includes(row.status); }); itemsToSearchCount = itemsToProcess.length; if (itemsToSearchCount === 0) { showStatus('没有需要自动查找链接的条目。', 'text-yellow-500', 4000); updateBatchProgress(0, 0); return; } showStatus(`开始批量自动查找 ${itemsToSearchCount} 个条目...`, 'text-blue-500'); updateBatchProgress(0, itemsToSearchCount); for (const row of itemsToProcess) { const doiHeaderForLoop = findHeader(Object.keys(row), COLUMN_MAPPING.doi); let doiValueForApi = null; if (doiHeaderForLoop && row[doiHeaderForLoop] != null) { doiValueForApi = String(row[doiHeaderForLoop]).trim(); if (doiValueForApi === "") doiValueForApi = null; } console.log(`[autoFindAllPdfs] Batching: Row: ${row._id}, DOI: ${doiValueForApi}`); await new Promise(resolve => setTimeout(resolve, 100)); promises.push( handleAutoFindPdfLink(doiValueForApi, row._id) .finally(() => { completedCount++; updateBatchProgress(completedCount, itemsToSearchCount); }) ); } Promise.allSettled(promises).then(() => { showStatus(`批量自动查找完成 ${itemsToSearchCount} 项尝试。`, 'text-green-500'); }); }
    async function downloadAllAvailablePdfs() { /* ... (不变, 包含最新的加载动画停止和失败条目状态更新逻辑) ... */ const backendApiUrlFromInput = backendApiUrlInput.value.trim(); if (!backendApiUrlFromInput) { alert('请输入后端API链接。'); backendApiUrlInput.focus(); return; } let baseBackendUrl = backendApiUrlFromInput; if (baseBackendUrl.includes('/api/find-pdf')) { baseBackendUrl = baseBackendUrl.substring(0, baseBackendUrl.lastIndexOf('/api/')); } else if (baseBackendUrl.endsWith('/')) { baseBackendUrl = baseBackendUrl.slice(0, -1); } const articlesToProcess = []; tableData.forEach(row => { if (row.pdfLink && row.pdfLink.trim() !== '' && !['自动查找中...', '自动查找失败', '链接无效', '下载失败'].includes(row.status)) { const titleHeader = findHeader(Object.keys(row), COLUMN_MAPPING.title); const currentTitle = (row[titleHeader] ? String(row[titleHeader]).trim() : '') || 'Untitled_Document_' + row._id.slice(-5); const doiHeader = findHeader(Object.keys(row), COLUMN_MAPPING.doi); const currentDoi = row[doiHeader] ? String(row[doiHeader]).trim() : null; articlesToProcess.push({ pdfLink: row.pdfLink, title: currentTitle, doi: currentDoi }); } }); if (articlesToProcess.length === 0) { showStatus('没有可供批量下载的链接。', 'text-yellow-500', 4000); return; } if (batchZipProcessingLoader) batchZipProcessingLoader.classList.remove('hidden'); const processingMessage = `后端正在处理 ${articlesToProcess.length} 个文献并打包ZIP...`; if (statusMessage) { statusMessage.textContent = processingMessage; statusMessage.className = 'mb-6 text-center text-sm font-medium text-blue-500';} if (downloadAllButton) downloadAllButton.disabled = true; const payload = { articles: articlesToProcess }; const batchApiUrl = `${baseBackendUrl}/api/batch_process_and_zip`; try { const response = await fetch(batchApiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); const responseData = await response.json(); if (batchZipProcessingLoader) batchZipProcessingLoader.classList.add('hidden'); if (!response.ok) { throw new Error(responseData.error || responseData.message || `服务器错误: ${response.status}`); } if (responseData.status === "previously_processed") { const userChoice = confirm( `此列表之前已打包为 "${responseData.zip_download_filename}" (${responseData.original_record_timestamp || ''}).\n\n[确定] 重新下载旧包，[取消] 删除旧记录并重处理?`); if (userChoice) { showStatus(`准备重新下载: ${responseData.zip_download_filename}`, 'text-blue-500'); triggerZipDownload(baseBackendUrl, responseData.zip_download_filename); setTimeout(() => showStatus(`已尝试重新下载: ${responseData.zip_download_filename}`, 'text-green-500'), 3000); } else { const delAndReproc = confirm(`删除旧记录 (${responseData.zip_download_filename}) 并重新为此列表生成新包?`); if (delAndReproc) { showStatus(`请求删除旧记录 (ID: ${responseData.task_id})...`, 'text-orange-500'); if (await deleteOldBatchRecord(baseBackendUrl, responseData.task_id)) { alert("旧记录已删。请重试“批量下载为ZIP”。"); showStatus('旧记录已删，请重试批量下载。', 'text-green-500'); } else { showStatus('删除旧记录失败。', 'text-red-500'); } } else { showStatus('操作已取消。', 'text-gray-500'); } } } else if (responseData.success && responseData.zip_download_filename) { triggerZipDownload(baseBackendUrl, responseData.zip_download_filename); setTimeout(() => { let finalMsg = `新ZIP包 "${responseData.zip_download_filename}" 已开始下载。处理 ${responseData.successfully_processed||0}/${responseData.total_requested||0} 文件。`; const failedCount = (responseData.total_requested||0) - (responseData.successfully_processed||0); if (failedCount > 0) { finalMsg += ` <strong class="text-red-600">${failedCount} 个文件处理失败。</strong>详情请查看失败列表。`; if (responseData.failed_items) { responseData.failed_items.forEach(item => { const orgRow = tableData.find(r => (item.doi && r[findHeader(Object.keys(r),COLUMN_MAPPING.doi)]===item.doi) || (!item.doi && r[findHeader(Object.keys(r),COLUMN_MAPPING.title)]===item.title)); if(orgRow) updateTableData(orgRow._id,'status','下载失败');});} if (showFailedButton) { showFailedButton.classList.add('animate-pulse','bg-red-700','ring-2','ring-red-300'); setTimeout(()=>showFailedButton.classList.remove('animate-pulse','bg-red-700','ring-2','ring-red-300'),7000);} showStatus(finalMsg, 'text-orange-600'); } else { finalMsg += ` 全部成功！`; showStatus(finalMsg, 'text-green-500');} }, 100); } else { throw new Error(responseData.error || responseData.message || '批量下载响应无效'); } } catch (error) { if (batchZipProcessingLoader) batchZipProcessingLoader.classList.add('hidden'); showStatus(`批量下载出错: ${error.message}`, 'text-red-500'); } finally { if (downloadAllButton) downloadAllButton.disabled = false; if (batchZipProcessingLoader && !batchZipProcessingLoader.classList.contains('hidden')) { batchZipProcessingLoader.classList.add('hidden'); } } }
    function triggerZipDownload(baseBackendUrl, zipFileName) { /* ... (不变) ... */ const zipDownloadUrl = `${baseBackendUrl}/api/download_zip_package/${zipFileName}`; const downloadLink = document.createElement('a'); downloadLink.href = zipDownloadUrl; document.body.appendChild(downloadLink); downloadLink.click(); document.body.removeChild(link); console.log(`[BatchDownload] Triggered ZIP download for: ${zipFileName}`); }
    async function deleteOldBatchRecord(baseBackendUrl, taskId) { /* ... (不变) ... */ if (!taskId) { console.error('[DelRecord] Task ID missing.'); return false; } try { const resp = await fetch(`${baseBackendUrl}/api/delete_batch_record`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ task_id: taskId }) }); const data = await resp.json(); return resp.ok && data.success; } catch (err) { console.error(`[DelRecord] Network error for task ${taskId}`, err); return false; } }
    function downloadSinglePdf(url, filenamePrefixSuggestion, rowId) { /* ... (不变) ... */ if (!url || !url.trim().toLowerCase().startsWith('http')) { alert(`无效的URL: ${url}`); updateTableData(rowId, 'status', '链接无效'); return; } const a = document.createElement('a'); a.href = url; a.target = '_blank'; const sanitizedPrefix = (filenamePrefixSuggestion || 'document').replace(/[^a-z0-9_.\-\s]/gi, '_').substring(0, 80).replace(/\s+/g, '_'); a.download = `${sanitizedPrefix}_${Date.now()}.pdf`; document.body.appendChild(a); try { a.click(); updateTableData(rowId, 'status', '打开/下载尝试'); } catch (e) { console.error("Dl/Open err:", e); updateTableData(rowId, 'status', '打开/下载失败'); alert(`无法打开/下载: ${e.message}`); } document.body.removeChild(a); }
    function downloadUploadTemplate() { /* ... (不变) ... */ const templateHeaders = [ COLUMN_MAPPING.doi[0], COLUMN_MAPPING.title[0], COLUMN_MAPPING.authors[0], COLUMN_MAPPING.year[0], COLUMN_MAPPING.source[0] ]; const headerRowString = templateHeaders.map(header => escapeCsvCell(header)).join(','); let csvContent = "\uFEFF"; csvContent += headerRowString + "\r\n"; const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' }); const link = document.createElement("a"); if (link.download !== undefined) { const url = URL.createObjectURL(blob); link.setAttribute("href", url); link.setAttribute("download", "文献上传模板.csv"); link.style.visibility = 'hidden'; document.body.appendChild(link); link.click(); document.body.removeChild(link); URL.revokeObjectURL(url); showStatus('上传模板文件已开始下载。', 'text-green-500', 3000); } else { alert('您的浏览器不支持直接下载。请手动复制以下表头并创建CSV文件：\n\n' + headerRowString); showStatus('无法直接下载模板，请手动复制表头。', 'text-yellow-500', 5000); } }
    function showFailedItemsModal() { /* ... (不变, 确保使用全局 tableData 和正确的DOM ID) ... */ if (!failedItemsTableContainer || !noFailedItemsMessageElem) { console.error("Failed items modal elements not found!"); return; } failedItemsTableContainer.innerHTML = ''; const failedStatuses = ['未找到', '下载失败', '链接无效', '自动查找失败']; const failedEntries = tableData.filter(row => failedStatuses.includes(row.status)); if (failedEntries.length > 0) { const table = document.createElement('table'); table.className = "min-w-full divide-y divide-gray-300"; const thead = document.createElement('thead'); thead.className = "bg-gray-100"; thead.innerHTML = `<tr><th scope="col" class="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">标题</th><th scope="col" class="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">DOI</th><th scope="col" class="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">原因(状态)</th></tr>`; table.appendChild(thead); const tbody = document.createElement('tbody'); tbody.className = "bg-white divide-y divide-gray-200"; failedEntries.forEach(row => { const tr = document.createElement('tr'); const titleH = findHeader(Object.keys(row), COLUMN_MAPPING.title); const doiH = findHeader(Object.keys(row), COLUMN_MAPPING.doi); tr.innerHTML = `<td class="px-4 py-3 text-sm text-gray-700 whitespace-normal">${truncateText(String(row[titleH]||'N/A'),100)}</td><td class="px-4 py-3 text-sm text-gray-500 whitespace-nowrap font-mono">${String(row[doiH]||'N/A')}</td><td class="px-4 py-3 text-sm text-red-600 whitespace-nowrap">${row.status}</td>`; tbody.appendChild(tr); }); table.appendChild(tbody); failedItemsTableContainer.appendChild(table); noFailedItemsMessageElem.classList.add('hidden'); } else { noFailedItemsMessageElem.classList.remove('hidden'); if(failedItemsTableContainer) failedItemsTableContainer.innerHTML='';} if (failedListModal) failedListModal.style.display = 'block'; }

    // PDF.js Rendering and Control functions

    // PDF.js Rendering and Control functions
    function renderPdfPage(num) {
        if (!pdfDoc || !pdfCanvas) {
            console.warn("renderPdfPage: pdfDoc or pdfCanvas not available.");
            pageRendering = false;
            updateZoomControls(); // 确保在无法渲染时也更新缩放控件状态
            return Promise.reject(new Error("PDF document or canvas not ready."));
        }

        // 如果当前有渲染任务正在进行，取消它
        if (currentRenderTask && typeof currentRenderTask.cancel === 'function') {
            console.log("renderPdfPage: Cancelling previous render task.");
            currentRenderTask.cancel();
            // 注意：currentRenderTask.cancel() 本身不一定会立即停止所有操作，
            // 但它会设置一个标志，使得后续的渲染操作（如果支持）可以提前退出。
            // 我们将 pageRendering 设为 false，稍后在开始新渲染时再设为 true。
            pageRendering = false;
        }

        pageRendering = true; // 设置页面正在渲染的标志
        if (pageNumSpan) pageNumSpan.textContent = num; // 更新显示的当前页码

        // 每次渲染新页面或新缩放级别时，尝试将PDF容器滚动到顶部
        const pdfCanvasContainerElem = document.getElementById('pdfCanvasContainer');
        if (pdfCanvasContainerElem) {
            pdfCanvasContainerElem.scrollTop = 0;
            pdfCanvasContainerElem.scrollLeft = 0; // 也重置水平滚动
        }

        return pdfDoc.getPage(num).then(function(page) {
            console.log('Page loaded:', num, 'at scale:', currentPdfScale);

            // 使用当前的缩放比例获取视口
            const viewport = page.getViewport({ scale: currentPdfScale });

            const canvasContext = pdfCanvas.getContext('2d');
            pdfCanvas.height = viewport.height;
            pdfCanvas.width = viewport.width;

            // 更新选框画布（selectionCanvas）的尺寸以完全匹配pdfCanvas
            const selCanvas = document.getElementById('selectionCanvas');
            if (selectionCtx) { // selectionCtx 是在DOMContentLoaded中获取的全局变量
                selectionCtx.clearRect(0, 0, selCanvas.width, selCanvas.height); // 清除旧的选框
            }
            if (selCanvas) {
                selCanvas.width = pdfCanvas.width;
                selCanvas.height = pdfCanvas.height;
                if(!selectionCtx) selectionCtx = selCanvas.getContext('2d');
            }

            // 每次重新渲染页面（包括缩放）后，都隐藏截图按钮，直到用户重新框选
            const capBtn = document.getElementById('captureSelectionBtn');
            if (capBtn) {
                capBtn.classList.add('hidden');
            }
            // 重置框选状态变量
            isSelecting = false;
            selectionRect = { startX: 0, startY: 0, endX: 0, endY: 0, pageNum: 0, finalX: 0, finalY: 0, finalWidth: 0, finalHeight: 0 };


            const renderContext = {
                canvasContext: canvasContext,
                viewport: viewport
            };

            currentRenderTask = page.render(renderContext); // 开始新的渲染任务

            return currentRenderTask.promise.then(function() {
                pageRendering = false; // 渲染完成
                currentRenderTask = null;
                console.log('Page rendered successfully:', num, 'at scale:', currentPdfScale);

                if (pageNumPending !== null) { // 如果有待处理的页面渲染请求
                    const pending = pageNumPending;
                    pageNumPending = null;
                    return queueRenderPage(pending); // 渲染待处理的页面
                }

                updatePdfNavButtons(); // 更新上一页/下一页按钮的状态
                updateZoomControls();  // 更新缩放控件的状态和显示
                return true;
            });
        }).catch(function(error) {
            pageRendering = false; // 渲染失败
            currentRenderTask = null;
            console.error(`Error rendering page ${num} at scale ${currentPdfScale}:`, error);

            // 避免对 "RenderingCancelledException" 或类似消息过多提示
            if (error && error.name !== 'RenderingCancelledException' &&
                error.message && !error.message.toLowerCase().includes('cancelled')) {
                showStatus(`渲染PDF页面 ${num} (缩放 ${Math.round(currentPdfScale*100)}%) 失败: ${error.message}`, 'text-red-500', 4000);
            }

            updatePdfNavButtons(); // 更新上一页/下一页按钮的状态
            updateZoomControls();  // 更新缩放控件的状态和显示
            return Promise.reject(error); // 将错误继续传递下去
        });
    }
    function updateZoomControls() {
        // 这些DOM元素是在 DOMContentLoaded 中获取的，这里直接使用
        // const zoomLevelSpan = document.getElementById('zoomLevelSpan');
        // const zoomInBtn = document.getElementById('zoomInBtn');
        // const zoomOutBtn = document.getElementById('zoomOutBtn');
        // 为确保函数在任何时候被调用都能安全执行，可以再次检查元素是否存在

        const zoomLevelSpanElem = document.getElementById('zoomLevelSpan'); // 直接获取，不依赖外部 const
        const zoomInBtnElem = document.getElementById('zoomInBtn');
        const zoomOutBtnElem = document.getElementById('zoomOutBtn');

        if (zoomLevelSpanElem) {
            zoomLevelSpanElem.textContent = `${Math.round(currentPdfScale * 100)}%`;
        }
        if (zoomInBtnElem) {
            zoomInBtnElem.disabled = (!pdfDoc || pageRendering || currentPdfScale >= MAX_PDF_SCALE);
        }
        if (zoomOutBtnElem) {
            zoomOutBtnElem.disabled = (!pdfDoc || pageRendering || currentPdfScale <= MIN_PDF_SCALE);
        }
    }
    function updatePdfNavButtons() { if (!pdfDoc || !prevPageBtn || !nextPageBtn) return; prevPageBtn.disabled = (currentPageNum <= 1); nextPageBtn.disabled = (currentPageNum >= pdfDoc.numPages); }
    function queueRenderPage(num) { if (pageRendering) { pageNumPending = num; console.log(`Queueing page ${num}`); if (currentRenderTask && typeof currentRenderTask.cancel === 'function') { currentRenderTask.cancel(); } } else { renderPdfPage(num).catch(err => { console.warn("Queued page render eventually failed:", err); }); } }
    function onPrevPage() { if (currentPageNum <= 1) return; currentPageNum--; queueRenderPage(currentPageNum); }
    function onNextPage() { if (!pdfDoc || currentPageNum >= pdfDoc.numPages) return; currentPageNum++; queueRenderPage(currentPageNum); }
    async function handlePdfFileSelected(event) {
        const file = event.target.files[0]; // 获取用户选择的第一个文件

        if (file) { // 如果用户确实选择了一个文件
            if (file.type === "application/pdf") {
                console.log("[handlePdfFileSelected] PDF file selected by user:", file.name);
                // 调用新的函数来处理 File 对象，这个函数内部会处理UI更新（如状态消息和标题）
                loadPdfFileObjectIntoViewer(file);
            } else {
                // 如果选择了文件但不是PDF类型
                alert("请选择一个有效的PDF文件 (文件类型应为 .pdf)。");
                showStatus("选择的文件不是有效的PDF格式。", "text-red-500", 3000);
            }
        } else {
            // 用户可能在文件选择对话框中点击了“取消”，此时 file 会是 undefined
            console.log("[handlePdfFileSelected] No file selected or selection cancelled by user.");
            // 这种情况下通常不需要给用户明确提示，因为是用户主动取消的
        }

        // 无论用户是否成功选择了有效文件，都重置文件选择器的值
        // 这样做是为了确保即使用户下次选择完全相同的文件，也能再次触发 'change' 事件
        if (event.target) {
            event.target.value = null;
        }
    }

    async function loadPdfFileObjectIntoViewer(fileObject) {
        if (!fileObject || fileObject.type !== "application/pdf") {
            alert("提供的文件无效或不是PDF。");
            showStatus("加载本地PDF文件失败：文件无效。", "text-red-500");
            updateZoomControls(); // ***** 新增: 即使加载失败，也更新控件状态 *****
            return;
        }
        currentPdfFileObject = fileObject;
        showStatus('正在加载本地PDF文件...', 'text-blue-500');

        if (pdfViewerTitle && currentViewingArticleRowId) {
            const rowData = tableData.find(r => r._id === currentViewingArticleRowId);
            if(rowData) {
                 const titleHeader = findHeader(Object.keys(rowData), COLUMN_MAPPING.title);
                 const actualTitle = rowData[titleHeader] ? String(rowData[titleHeader]).trim() : null;
                 pdfViewerTitle.textContent = actualTitle ? truncateText(actualTitle, 50) : `PDF: ${truncateText(fileObject.name, 30)}`;
            } else {
                 pdfViewerTitle.textContent = truncateText(fileObject.name, 40);
            }
        } else if (pdfViewerTitle) {
             pdfViewerTitle.textContent = truncateText(fileObject.name, 40);
        }

        // ***** 新增/修改：重置缩放比例为默认值并更新控件 *****
        currentPdfScale = 1.5; // 设置为您希望的默认初始比例 (例如 150%)
        updateZoomControls();
        // ***** 结束新增/修改 *****

        const fileReader = new FileReader();
        fileReader.onload = async function() {
            const typedarray = new Uint8Array(this.result);
            try {
                // 清理上一个PDF文档对象（如果存在）
                if (pdfDoc) {
                    await pdfDoc.destroy(); // 销毁旧的PDF文档对象以释放资源
                    pdfDoc = null;
                    console.log("Previous pdfDoc destroyed.");
                }

                const loadingTask = pdfjsLib.getDocument({ data: typedarray });
                pdfDoc = await loadingTask.promise;
                console.log("New pdfDoc loaded.");

                if (pageCountSpan) pageCountSpan.textContent = pdfDoc.numPages;
                currentPageNum = 1; // 总是从第一页开始

                updatePdfNavButtons(); // ***** 新增/确保调用: 更新翻页按钮状态 *****
                updateZoomControls();  // ***** 再次调用: 确保缩放控件基于新文档状态更新 *****

                // 清除旧的选框画布内容 (如果 renderPdfPage 不会完全覆盖的话)
                if (selectionCtx) {
                    const selCanvas = document.getElementById('selectionCanvas');
                    if (selCanvas) selectionCtx.clearRect(0, 0, selCanvas.width, selCanvas.height);
                }


                renderPdfPage(currentPageNum)
                    .then(() => {
                        showStatus('本地PDF加载完成。', 'text-green-500', 2000);
                        displayScreenshotsForCurrentArticle();
                    })
                    .catch(error => {
                        console.error("Local PDF initial page render failed:", error);
                        // renderPdfPage 内部的 catch 已经调用了 showStatus
                    });
            } catch (error) {
                console.error('Local PDF load err:', error);
                showStatus(`加载本地PDF失败: ${error.message}`, 'text-red-500');
                pdfDoc = null; // 确保 pdfDoc 在出错时被设为 null
                if(pdfCanvas) { const ctx = pdfCanvas.getContext('2d'); if(ctx) ctx.clearRect(0,0,pdfCanvas.width,pdfCanvas.height); }
                if(pageNumSpan) pageNumSpan.textContent='0';
                if(pageCountSpan) pageCountSpan.textContent='0';
                updatePdfNavButtons(); // 更新翻页按钮
                updateZoomControls();  // 出错时也更新缩放控件
            }
        };
        fileReader.onerror = (error) => { // FileReader 本身的错误
            console.error("FileReader error:", error);
            showStatus(`读取文件失败: ${error.message || '未知错误'}`, "text-red-500");
            updateZoomControls(); // 更新控件状态
        };
        fileReader.readAsArrayBuffer(fileObject);
    }
    // --- 框选逻辑 ---
    if (selectionCanvas && pdfCanvasContainer) {
        selectionCanvas.addEventListener('mousedown', (e) => {
            if (!pdfDoc || pageRendering) return; isSelecting = true;
            const rect = selectionCanvas.getBoundingClientRect();
            selectionRect.startX = e.clientX - rect.left; selectionRect.startY = e.clientY - rect.top;
            selectionRect.endX = selectionRect.startX; selectionRect.endY = selectionRect.startY;
            selectionRect.pageNum = currentPageNum;
            if (selectionCtx) selectionCtx.clearRect(0, 0, selectionCanvas.width, selectionCanvas.height);
            if (captureSelectionBtn) captureSelectionBtn.classList.add('hidden');
        });
        selectionCanvas.addEventListener('mousemove', (e) => {
            if (!isSelecting || !selectionCtx) return;
            const rect = selectionCanvas.getBoundingClientRect();
            selectionRect.endX = e.clientX - rect.left; selectionRect.endY = e.clientY - rect.top;
            selectionCtx.clearRect(0, 0, selectionCanvas.width, selectionCanvas.height);
            selectionCtx.strokeStyle = 'red'; selectionCtx.lineWidth = 1;
            selectionCtx.strokeRect(selectionRect.startX, selectionRect.startY, selectionRect.endX - selectionRect.startX, selectionRect.endY - selectionRect.startY);
        });
        selectionCanvas.addEventListener('mouseup', (e) => {
            if (!isSelecting) return; isSelecting = false;
            const rect = selectionCanvas.getBoundingClientRect();
            selectionRect.endX = e.clientX - rect.left; selectionRect.endY = e.clientY - rect.top;
            const x = Math.min(selectionRect.startX, selectionRect.endX);
            const y = Math.min(selectionRect.startY, selectionRect.endY);
            const width = Math.abs(selectionRect.endX - selectionRect.startX);
            const height = Math.abs(selectionRect.endY - selectionRect.startY);
            if (width > 5 && height > 5) {
                selectionRect.finalX = x; selectionRect.finalY = y; selectionRect.finalWidth = width; selectionRect.finalHeight = height;
                if (captureSelectionBtn) captureSelectionBtn.classList.remove('hidden');
            } else {
                if (selectionCtx) selectionCtx.clearRect(0, 0, selectionCanvas.width, selectionCanvas.height);
                if (captureSelectionBtn) captureSelectionBtn.classList.add('hidden');
            }
        });
        selectionCanvas.addEventListener('mouseleave', (e) => {
            if (isSelecting) {
                isSelecting = false;
                const x = Math.min(selectionRect.startX, selectionRect.endX); const y = Math.min(selectionRect.startY, selectionRect.endY);
                const width = Math.abs(selectionRect.endX - selectionRect.startX); const height = Math.abs(selectionRect.endY - selectionRect.startY);
                if (width > 5 && height > 5) {
                    selectionRect.finalX = x; selectionRect.finalY = y; selectionRect.finalWidth = width; selectionRect.finalHeight = height;
                    if (captureSelectionBtn) captureSelectionBtn.classList.remove('hidden');
                } else {
                    if (selectionCtx) selectionCtx.clearRect(0, 0, selectionCanvas.width, selectionCanvas.height);
                    if (captureSelectionBtn) captureSelectionBtn.classList.add('hidden');
                }
            }
        });
    }

    // --- 截图按钮事件监听 ---
    // 这个函数应该在您的 script.js 文件中，DOMContentLoaded 事件监听器的内部

// --- 截图按钮事件监听 ---
    if (captureSelectionBtn && pdfCanvas) { // 确保 pdfCanvas 也可访问
        captureSelectionBtn.addEventListener('click', async () => { // <--- 修改为 async 函数
            if (!selectionRect.finalWidth || !selectionRect.finalHeight || selectionRect.finalWidth <= 0 || selectionRect.finalHeight <= 0) {
               alert("请先在PDF页面上框选一个有效的区域。");
               return;
           }
           if (!currentViewingArticleRowId) {
               alert("无法确定当前操作的文献，请重新打开PDF查看器并选择文献。");
               return;
           }

           const currentArticleRow = tableData.find(r => r._id === currentViewingArticleRowId);
           if (!currentArticleRow) {
               console.error(`[CaptureScreenshot] Critical: Could not find article data for rowId: ${currentViewingArticleRowId}`);
               alert("无法找到当前文献数据来保存截图记录，操作失败。");
               return;
           }

           showStatus('正在处理截图并上传到服务器...', 'text-blue-500'); // <--- 新增：初始状态提示

           // 1. 创建临时canvas并绘制选区 (用于获取原图数据)
           const tempCanvas = document.createElement('canvas');
           tempCanvas.width = selectionRect.finalWidth;
           tempCanvas.height = selectionRect.finalHeight;
           const tempCtx = tempCanvas.getContext('2d');
           if (!pdfCanvas) { // 以防万一
               alert("PDF渲染画布未找到，无法截图。");
               showStatus('截图失败：PDF渲染画布丢失。', 'text-red-500', 3000);
               return;
           }
           tempCtx.drawImage(
               pdfCanvas, // 源canvas (渲染了PDF页面的那个)
               selectionRect.finalX, selectionRect.finalY,
               selectionRect.finalWidth, selectionRect.finalHeight,
               0, 0, selectionRect.finalWidth, selectionRect.finalHeight
           );
           const dataURLForApi = tempCanvas.toDataURL('image/png'); // <--- 原图数据，用于发送给API

           // 2. 创建和绘制缩略图 (用于前端预览和本地存储)
           const THUMBNAIL_MAX_WIDTH = 100;
           const THUMBNAIL_MAX_HEIGHT = 80;
           const thumbnailCanvas = document.createElement('canvas');
           const aspectRatio = selectionRect.finalWidth / selectionRect.finalHeight;

           if (selectionRect.finalWidth === 0 || selectionRect.finalHeight === 0) {
               console.error("[CaptureSS] Invalid selection rectangle for thumbnail (zero width/height).");
               showStatus('截图失败：选区大小无效。', 'text-red-500', 3000);
               return;
          }

           if (aspectRatio > THUMBNAIL_MAX_WIDTH / THUMBNAIL_MAX_HEIGHT) {
               thumbnailCanvas.width = THUMBNAIL_MAX_WIDTH;
               thumbnailCanvas.height = Math.max(1, THUMBNAIL_MAX_WIDTH / aspectRatio);
           } else {
               thumbnailCanvas.height = THUMBNAIL_MAX_HEIGHT;
               thumbnailCanvas.width = Math.max(1, THUMBNAIL_MAX_HEIGHT * aspectRatio);
           }

           const thumbCtx = thumbnailCanvas.getContext('2d');
           if (tempCanvas.width > 0 && tempCanvas.height > 0) {
               thumbCtx.drawImage(
                   tempCanvas,
                   0, 0, tempCanvas.width, tempCanvas.height,
                   0, 0, thumbnailCanvas.width, thumbnailCanvas.height
               );
           }
           const thumbnailDataUrl = thumbnailCanvas.toDataURL('image/png'); // <--- 缩略图数据

           // 3. 准备发送给后端API的数据
           let baseFilenameForSuggestion = '图表截图';
           const titleHeader = findHeader(Object.keys(currentArticleRow), COLUMN_MAPPING.title);
           const articleTitle = currentArticleRow[titleHeader] ? String(currentArticleRow[titleHeader]).trim() : '';
           if (articleTitle) {
               baseFilenameForSuggestion = truncateText(sanitizeFilenameForImage(articleTitle), 30);
           }
           const existingScreenshotsCount = currentArticleRow.screenshots?.length || 0;
           const suggestedFilenameForPayload = `${baseFilenameForSuggestion}_Page${selectionRect.pageNum}_Selection${existingScreenshotsCount + 1}.png`;

           const payload = {
               articleId: currentViewingArticleRowId,
               articleTitle: articleTitle || "Untitled Article", // 提供一个默认值
               pageNumber: selectionRect.pageNum,
               selectionRect: {
                   x: selectionRect.finalX,
                   y: selectionRect.finalY,
                   width: selectionRect.finalWidth,
                   height: selectionRect.finalHeight
               },
               imageData: dataURLForApi,
               suggestedFilename: suggestedFilenameForPayload,
               chartType: "未指定", // 初始值
               description: ""     // 初始值
           };

           // 4. 发起API调用
           const backendApiUrlInputElem = document.getElementById('backendApiUrlInput'); // 获取输入框元素
           if (!backendApiUrlInputElem || !backendApiUrlInputElem.value) {
               alert('后端API链接未配置，无法保存截图到服务器。请在设置中填写。');
               showStatus('截图上传失败：后端API链接未配置。', 'text-red-500', 5000);
               if(selectionCtx) selectionCtx.clearRect(0, 0, selectionCanvas.width, selectionCanvas.height); // 清理选框
               if(captureSelectionBtn) captureSelectionBtn.classList.add('hidden');                         // 隐藏按钮
               return;
           }
            const baseApiUrl = backendApiUrlInputElem.value.trim().replace(/\/$/, ""); // 移除末尾斜杠
            const saveScreenshotApiUrl = `${baseApiUrl}/api/save_screenshot`;

            try {
               const response = await fetch(saveScreenshotApiUrl, {
                   method: 'POST',
                   headers: {
                       'Content-Type': 'application/json'
                   },
                   body: JSON.stringify(payload)
               });

               const responseData = await response.json();

               if (response.ok && responseData.success) {
                // 5. 后端成功保存，更新前端数据
                   const screenshotRecord = {
                       id: `ss-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`, // 前端ID
                       pageNumber: selectionRect.pageNum,
                       rect: payload.selectionRect,
                       filenameSuggested: suggestedFilenameForPayload, // 可以考虑用 responseData.serverFilePath 的文件名部分
                       chartType: "未指定",
                       description: "",
                       timestamp: new Date().toISOString(),
                       thumbnailDataUrl: thumbnailDataUrl, // 保存缩略图用于预览

                       // 从服务器响应获取的信息
                       serverScreenshotId: responseData.screenshotServerId || null, // 后端可能不返回这个
                       serverFilePath: responseData.serverFilePath,
                       serverMetadataPath: responseData.metadataFilePath
                   };

                   if (!currentArticleRow.screenshots) {
                       currentArticleRow.screenshots = [];
                   }
                   currentArticleRow.screenshots.push(screenshotRecord);
                   saveTableDataToLocalStorage();
                   displayScreenshotsForCurrentArticle(); // 刷新截图列表

                   showStatus(`截图已成功保存到服务器！路径: ${responseData.serverFilePath}`, 'text-green-500', 5000);
                   console.log("[CaptureSS] Screenshot saved to server. Frontend record:", screenshotRecord);

               } else {
                   // 后端返回错误或 success: false
                   throw new Error(responseData.message || `服务器返回错误: ${response.status}`);
               }

           } catch (error) {
               console.error('[CaptureSS] Error saving screenshot to server:', error);
               showStatus(`截图保存到服务器失败: ${error.message}`, 'text-red-500', 7000);
            // 此时不保存本地记录，以保持数据一致性
           } finally {
               // 6. 清理操作
               if(selectionCtx) selectionCtx.clearRect(0, 0, selectionCanvas.width, selectionCanvas.height);
               if(captureSelectionBtn) captureSelectionBtn.classList.add('hidden');
           }
       });
    }

    // --- 页面加载完成后的初始化 ---
    const dataLoaded = loadTableDataFromLocalStorage();
    if (statusFilterSelect && typeof currentStatusFilter !== 'undefined') {
        statusFilterSelect.value = currentStatusFilter;
    }
    applyFiltersAndSort();

}); // --- DOMContentLoaded 事件监听器结束 ---
