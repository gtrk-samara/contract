// Инициализация глобальных констант и модальных окон
const contractsTable = document.getElementById("contractsTable");
const deleteModal = new bootstrap.Modal(document.getElementById("deleteContractModal"));
const settingsModal = new bootstrap.Modal(document.getElementById("settingsModal"));
const notificationModal = new bootstrap.Modal(document.getElementById('notificationModal'));
const loginModal = new bootstrap.Modal(document.getElementById('loginModal'));
const BASE_URL = localStorage.getItem("backendUrl") || "http://localhost:8080";

// Функция переключения видимости пароля
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const icon = document.getElementById(inputId + "ToggleIcon");
    if (input.type === "password") {
        input.type = "text";
        icon.classList.remove("bi-eye");
        icon.classList.add("bi-eye-slash");
    } else {
        input.type = "password";
        icon.classList.remove("bi-eye-slash");
        icon.classList.add("bi-eye");
    }
}

// Функция проверки валидности токена
async function validateToken() {
    console.log("[DEBUG] Начало проверки токена");
    const token = localStorage.getItem("authToken");
    if (!token) {
        console.log("[DEBUG] Токен отсутствует в localStorage");
        localStorage.removeItem("authToken");
        localStorage.removeItem("userRole");
        return false;
    }

    try {
        console.log("[DEBUG] Отправка запроса на проверку токена");
        const response = await fetch(`${BASE_URL}/validate-token`, {
            method: 'GET',
            headers: { "Authorization": `Bearer ${token}` }
        });
        console.log("[DEBUG] Статус ответа:", response.status);
        if (!response.ok) {
            console.log("[DEBUG] Токен недействителен, статус:", response.status);
            localStorage.removeItem("authToken");
            localStorage.removeItem("userRole");
            return false;
        }
        console.log("[DEBUG] Токен валиден");
        return true;
    } catch (error) {
        console.error("[ERROR] Ошибка проверки токена:", error);
        localStorage.removeItem("authToken");
        localStorage.removeItem("userRole");
        return false;
    }
}

// Вспомогательная функция для выполнения запросов с токеном
async function fetchWithAuth(url, options = {}) {
    const token = localStorage.getItem("authToken");
    if (!token) {
        throw new Error("Токен авторизации отсутствует");
    }
    options.headers = {
        ...options.headers,
        "Authorization": `Bearer ${token}`
    };
    const response = await fetch(url, options);
    if (response.status === 401) {
        // Если токен недействителен, выполняем выход
        localStorage.removeItem("authToken");
        document.getElementById("logoutButton").click();
        throw new Error("Сессия истекла. Пожалуйста, войдите снова.");
    }
    return response;
}

// Показ уведомления в модальном окне
function showNotificationModal(message) {
    document.getElementById('notificationModalBody').innerText = message;
    notificationModal.show();
}

// Обновление интерфейса на основе роли пользователя
function updateUI() {
    const role = localStorage.getItem("userRole");
    const deleteContractButton = document.getElementById("deleteContractButton");
    const showCuratorsModalButton = document.getElementById("showCuratorsModal");
    const clearHistoryButton = document.getElementById("clearHistoryButton");
    const settingsButton = document.getElementById("settingsButton"); // Кнопка настроек
    const addUserButton = document.getElementById("addUserButton"); // Кнопка добавления пользователя
    const showUsersModalButton = document.getElementById("showUsersModal"); //Кнопка управления пользователями

    // Управление видимостью кнопки удаления договора
    if (deleteContractButton) {
        deleteContractButton.style.display = role === "admin" ? "block" : "none";
    }
      
    // Управление видимостью кнопки очистки истории
    if (clearHistoryButton) {
        clearHistoryButton.style.display = role === "admin" ? "block" : "none";
    }

    // Управление видимостью кнопки настроек
    if (settingsButton) {
        settingsButton.style.display = role === "admin" ? "block" : "none";
    }

    // Управление видимостью кнопки добавления пользователя
    if (addUserButton) {
        addUserButton.style.display = role === "admin" ? "block" : "none";
    }

    // Управление видимостью кнопки управления пользователями
    if (showUsersModalButton) {
        showUsersModalButton.style.display = role === "admin" ? "block" : "none";
    }
}

// Функция перевода роли на русский с заглавной буквы
function translateRole(role) {
    const roleMap = {
        "curator": "Куратор",
        "lawyer": "Юрист",
        "chief_accountant": "Главный бухгалтер",
        "chief_engineer": "Главный инженер",
        "admin": "Администратор"
    };
    return roleMap[role] || role;
}

// Обработка авторизации
document.getElementById("loginForm").onsubmit = async (e) => {
    e.preventDefault();
    try {
        const response = await fetch(`${BASE_URL}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                login: document.getElementById("loginInput").value.trim(),
                password: document.getElementById("passwordInput").value
            })
        });

        if (!response.ok) throw new Error(`Ошибка авторизации: ${await response.text()}`);

        const data = await response.json();
        console.log("Ответ сервера:", data); // Для отладки

        // Сохраняем данные
        localStorage.setItem("authToken", data.token);
        localStorage.setItem("userRole", data.role);
        localStorage.setItem("userFullName", data.user.fullName); // Сохраняем полное имя
        
        // Обновляем отображение
        document.getElementById("userInfo").innerText = 
            `Пользователь: ${data.user.fullName} (${translateRole(data.role)})`;
        
        document.getElementById("logoutButton").style.display = "inline-block";
        document.getElementById("mainContent").style.display = "block";
        loginModal.hide();
        updateUI();
        loadContracts();
    } catch (error) {
        console.error("Ошибка авторизации:", error);
        showNotificationModal("Не удалось войти: " + error.message);
    }
};

// Обработчик выхода
document.getElementById("logoutButton").addEventListener("click", () => {
    localStorage.removeItem("authToken"); // Удаляем токен
    localStorage.removeItem("userRole"); // Удаляем роль
    localStorage.removeItem("login"); // Добавляем удаление логина
    document.getElementById("userInfo").innerText = "";
    document.getElementById("logoutButton").style.display = "none";
    document.getElementById("mainContent").style.display = "none";
    document.getElementById("loginForm").reset();
    loginModal.show();
});

// Форматирование даты в формат ДД.ММ.ГГГГ
function formatDate(dateStr) {
    if (!dateStr) return "Не указана";
    const [year, month, day] = dateStr.split("-");
    return `${day}.${month}.${year}`;
}

// Извлечение имени файла из пути
function formatFilePath(filePath) {
    if (!filePath) return "Нет загруженного файла";
    return filePath.replace(/^.*[\\/]/, "");
}

// Получение пути к папке загрузки из localStorage
function getUploadFolder() {
    return localStorage.getItem("uploadFolder") || "D:\\contract\\uploads";
}

// Сохранение пути к папке загрузки
function saveUploadFolder(path) {
    if (path) localStorage.setItem("uploadFolder", path);
    document.getElementById("selectedFolderPath").innerText = `Текущая папка: ${getUploadFolder()}`;
    return true;
}

// Сортировка договоров по статусу
function sortContractsByStatus(contracts) {
    const statusOrder = {
        "Получение шаблона": 0,
        "Проверка инициатором": 1,
        "Согласование внутри компании": 2,
        "Согласование с контрагентом": 3,
        "Подписание": 4,
        "Исполнение": 5,
        "Завершен": 6
    };
    return contracts.sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);
}

// Загрузка списка контрагентов
async function loadCounterparties() {
    try {
        const response = await fetchWithAuth(`${BASE_URL}/counterparties`);
        if (!response.ok) throw new Error(`Ошибка загрузки контрагентов: ${response.statusText}`);
        const counterparties = await response.json();
        const datalist = document.getElementById("counterpartiesList");
        datalist.innerHTML = "";
        // Проверяем, является ли counterparties массивом
        if (!Array.isArray(counterparties)) {
            console.warn("[WARN] Ответ сервера для контрагентов не является массивом:", counterparties);
            return;
        }
        counterparties.forEach(cp => {
            const option = document.createElement("option");
            option.value = cp.name;
            datalist.appendChild(option);
        });
    } catch (error) {
        console.error("Ошибка в loadCounterparties:", error);
        alert("Не удалось загрузить контрагентов: " + error.message);
    }
}

// Загрузка договоров с фильтрацией
async function loadContracts(filter = "all") {
    console.log(`[LOG] Начало загрузки договоров с фильтром: ${filter}`);
    try {
        console.log(`[LOG] Отправка запроса на ${BASE_URL}/contracts`);
        const response = await fetchWithAuth(`${BASE_URL}/contracts`);
        console.log(`[LOG] Ответ сервера: статус ${response.status}`);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Ошибка загрузки договоров: ${response.statusText} - ${errorText}`);
        }
        const contracts = await response.json();
        if (!Array.isArray(contracts)) {
            console.error("[ERROR] Ответ сервера не является массивом:", contracts);
            throw new Error("Неверный формат данных: ожидался массив договоров");
        }
        console.log(`[DEBUG] Сырой ответ сервера:`, contracts);
        console.log(`[DEBUG] Полученные договоры:`, contracts.map(c => ({
            id: c.id,
            signed_file_path: c.signed_file_path,
            is_signed_electronically: c.is_signed_electronically
        })));
        contractsTable.innerHTML = "";
        const sortedContracts = sortContractsByStatus(contracts);
        sortedContracts.forEach(contract => {
            if (filter === "active" && contract.status === "Завершен") return;
            if (filter === "completed" && contract.status !== "Завершен") return;
            const row = document.createElement("tr");
            const statusClass = contract.status === "Завершен" ? "status-completed" : "";
            const lawyerStatusClass = contract.lawyer_status === "Согласовал" ? "status-highlight" : "";
            const chiefAccountantStatusClass = contract.chief_accountant_status === "Согласовал" ? "status-highlight" : "";
            const counterpartyStatusClass = contract.counterparty_status === "Согласовал" ? "status-highlight" : "";
            const contractStatusClass = contract.status === "Исполнение" ? "status-highlight" : 
                contract.status === "Подписание" ? "status-signing" : statusClass;
            const paperclipIcon = contract.signed_file_path ? ' <i class="bi bi-paperclip"></i>' : '';
            row.innerHTML = `
                <td>${contract.id}</td>
                <td>${formatDate(contract.date)}</td>
                <td>${contract.number || "Не указан"}</td>
                <td>
                    <strong>${contract.name}</strong>${paperclipIcon}
                    ${contract.is_signed_electronically ? '<span class="edo-label">ЭДО</span>' : ''}
                    <span class="curator-info">${contract.curator || "Куратор не указан"}</span>
                </td>
                <td class="supplier-cell">${contract.supplier}</td>
                <td class="counterparty-status-cell ${counterpartyStatusClass}">${contract.counterparty_status || ""}</td>
                <td class="${lawyerStatusClass}">${contract.lawyer_status || ""}</td>
                <td class="${chiefAccountantStatusClass}">${contract.chief_accountant_status || ""}</td>
                <td class="${contractStatusClass}">${contract.status}</td>
                <td></td>
            `;
            row.addEventListener("click", (e) => {
                if (e.target.tagName !== "BUTTON") showEditModal(contract);
            });
            contractsTable.appendChild(row);
        });
        console.log(`[LOG] Таблица обновлена, отображено ${contractsTable.children.length} строк`);
        await loadCounterparties();
        loadCurators();
    } catch (error) {
        console.error("[ERROR] Ошибка в loadContracts:", error);
        showNotificationModal("Не удалось загрузить договоры: " + error.message);
    }
}

// Получение ID контрагента по имени
async function getCounterpartyIdByName(name) {
    try {
        const response = await fetchWithAuth(`${BASE_URL}/counterparties`);
        if (!response.ok) throw new Error("Ошибка загрузки списка контрагентов");
        const counterparties = await response.json();
        const counterparty = counterparties.find(cp => cp.name === name);
        return counterparty ? counterparty.id : null;
    } catch (error) {
        console.error("Ошибка в getCounterpartyIdByName:", error);
        return null;
    }
}

// Загрузка кураторов
async function loadCurators() {
    try {
        console.log("[DEBUG] Загрузка кураторов");
        const response = await fetchWithAuth(`${BASE_URL}/curators`);
        if (!response.ok) throw new Error(`Ошибка загрузки кураторов: ${response.statusText}`);
        const curators = await response.json();
        console.log("[DEBUG] Получено кураторов:", curators.length);

        const select = document.getElementById("editCurator");
        if (!select) {
            console.warn("[WARN] Элемент editCurator не найден");
            return;
        }
        select.innerHTML = '';
        curators.forEach(curator => {
            const option = document.createElement("option");
            option.value = `${curator.surname} ${curator.name} ${curator.patronymic}`;
            option.text = `${curator.surname} ${curator.name} ${curator.patronymic}`;
            select.appendChild(option);
        });

        const curatorsTable = document.getElementById("curatorsTable");
        if (!curatorsTable) {
            console.warn("[WARN] Элемент curatorsTable не найден");
            return;
        }
        curatorsTable.innerHTML = "";
        curators.forEach(curator => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${curator.surname}</td>
                <td>${curator.name}</td>
                <td>${curator.patronymic}</td>
                <td><button class="btn btn-danger btn-sm delete-curator" data-id="${curator.id}"><i class="bi bi-trash"></i></button></td>
            `;
            curatorsTable.appendChild(row);
        });

        document.querySelectorAll(".delete-curator").forEach(btn => {
            btn.addEventListener("click", async () => {
                const id = btn.dataset.id;
                if (localStorage.getItem("userRole") !== "admin") {
                    showNotificationModal("Только администратор может удалять кураторов.");
                    return;
                }
                if (confirm("Вы уверены, что хотите удалить этого куратора?")) {
                    try {
                        const response = await fetchWithAuth(`${BASE_URL}/curators/${id}`, { method: "DELETE" });
                        if (!response.ok) {
                            const errorData = await response.json();
                            throw new Error(errorData.error || `Ошибка удаления: ${response.statusText}`);
                        }
                        showNotificationModal("Куратор успешно удалён!");
                        if (curatorsModalInstance) {
                            curatorsModalInstance.hide();
                            console.log("[DEBUG] Модальное окно кураторов закрыто");
                        }
                        loadCurators();
                        // Удаляем остаточные оверлеи
                        document.querySelectorAll(".modal-backdrop").forEach(backdrop => {
                            backdrop.remove();
                            console.log("[DEBUG] Удалён остаточный .modal-backdrop");
                        });
                        document.body.classList.remove("modal-open");
                        document.body.style.overflow = "";
                        console.log("[DEBUG] Класс modal-open удалён, стиль overflow сброшен");
                    } catch (error) {
                        console.error("[ERROR] Ошибка удаления куратора:", error);
                        showNotificationModal("Не удалось удалить куратора: " + error.message);
                    }
                }
            });
        });
    } catch (error) {
        console.error("[ERROR] Ошибка в loadCurators:", error);
        showNotificationModal("Не удалось загрузить кураторов: " + error.message);
    }
}

// Обработчик кнопки показа данных контрагента
document.getElementById("showCounterpartyDetailsButton").addEventListener("click", async () => {
    const supplierName = document.getElementById("editSupplier").value.trim();
    if (!supplierName) {
        alert("Пожалуйста, выберите контрагента.");
        return;
    }
    try {
        const counterpartyId = await getCounterpartyIdByName(supplierName);
        if (!counterpartyId) {
            alert("Контрагент с таким именем не найден.");
            return;
        }
        showCounterpartyDetails(counterpartyId);
    } catch (error) {
        console.error("Ошибка при загрузке данных контрагента:", error);
        alert("Не удалось загрузить данные контрагента: " + error.message);
    }
});

let currentCounterpartyId = null;

// Показ данных контрагента в модальном окне
async function showCounterpartyDetails(counterpartyId) {
    const response = await fetchWithAuth(`${BASE_URL}/counterparties/${counterpartyId}`);
    const counterparty = await response.json();
    currentCounterpartyId = counterparty.id;
    document.getElementById("counterpartyName").value = counterparty.name || "";
    document.getElementById("counterpartyINN").value = counterparty.inn || "";
    document.getElementById("counterpartyKPP").value = counterparty.kpp || "";
    document.getElementById("counterpartyOGRN").value = counterparty.ogrn || "";
    document.getElementById("counterpartyBIK").value = counterparty.bik || "";
    document.getElementById("counterpartyBankName").value = counterparty.bank_name || "";
    document.getElementById("counterpartyAccountNumber").value = counterparty.account_number || "";
    document.getElementById("counterpartyDirectorName").value = counterparty.director_name || "";
    document.getElementById("counterpartyDirectorPhone").value = counterparty.director_phone || "";
    document.getElementById("counterpartyManagerName").value = counterparty.manager_name || "";
    document.getElementById("counterpartyManagerPhone").value = counterparty.manager_phone || "";
    document.getElementById("counterpartyLegalAddress").value = counterparty.legal_address || "";
    document.getElementById("counterpartyPhysicalAddress").value = counterparty.physical_address || "";
    document.getElementById("counterpartyComment").value = counterparty.comment || "";
    const modal = new bootstrap.Modal(document.getElementById("counterpartyDetailsModal"));
    modal.show();
}

// Обработчик сохранения данных контрагента
document.getElementById("counterpartyDetailsForm").onsubmit = async (e) => {
    e.preventDefault();
    if (!currentCounterpartyId) {
        alert("ID контрагента не определен!");
        return;
    }
    const updatedCounterparty = {
        id: currentCounterpartyId,
        name: document.getElementById("counterpartyName").value,
        inn: document.getElementById("counterpartyINN").value || null,
        kpp: document.getElementById("counterpartyKPP").value || null,
        ogrn: document.getElementById("counterpartyOGRN").value || null,
        bik: document.getElementById("counterpartyBIK").value || null,
        bank_name: document.getElementById("counterpartyBankName").value || null,
        account_number: document.getElementById("counterpartyAccountNumber").value || null,
        director_name: document.getElementById("counterpartyDirectorName").value || null,
        director_phone: document.getElementById("counterpartyDirectorPhone").value || null,
        manager_name: document.getElementById("counterpartyManagerName").value || null,
        manager_phone: document.getElementById("counterpartyManagerPhone").value || null,
        legal_address: document.getElementById("counterpartyLegalAddress").value || null,
        physical_address: document.getElementById("counterpartyPhysicalAddress").value || null,
        comment: document.getElementById("counterpartyComment").value || null
    };
    try {
        const response = await fetchWithAuth(`${BASE_URL}/counterparties/${currentCounterpartyId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(updatedCounterparty)
        });
        if (!response.ok) throw new Error("Ошибка при сохранении данных контрагента: " + response.statusText);
        alert("Данные контрагента успешно обновлены!");
        bootstrap.Modal.getInstance(document.getElementById("counterpartyDetailsModal")).hide();
        loadCounterparties();
    } catch (error) {
        console.error("Ошибка:", error);
        alert("Произошла ошибка при сохранении: " + error.message);
    }
};

// Обработчик фильтра по статусу
document.getElementById("statusFilter").addEventListener("change", (e) => {
    loadContracts(e.target.value);
});

// Обработчик формы добавления договора
document.getElementById("addContractForm").onsubmit = async (e) => {
    e.preventDefault();
    const name = document.getElementById("addName").value;
    const number = document.getElementById("addNumber").value;
    const supplier = document.getElementById("addSupplier").value;
    const date = document.getElementById("addDate").value;
    const file = document.getElementById("addFile").files[0];
    const curator = document.getElementById("addCurator").value;
    const formData = new FormData();
    formData.append("name", name);
    formData.append("number", number);
    formData.append("supplier", supplier);
    formData.append("date", date);
    formData.append("curator", curator);
    if (file) formData.append("file", file);
    try {
        const response = await fetchWithAuth(`${BASE_URL}/contracts`, {
            method: "POST",
            body: formData
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error("Ошибка при создании договора: " + errorText);
        }
        const data = await response.json();
        showNotificationModal("Договор создан с ID: " + data.id);
        document.getElementById("addContractForm").reset();
        document.getElementById("addFilePath").innerText = "Нет загруженного файла";
        document.getElementById("addFile").value = "";
        bootstrap.Modal.getInstance(document.getElementById("addContractModal")).hide();
        loadContracts();
    } catch (error) {
        console.error("Ошибка:", error);
        showNotificationModal("Произошла ошибка при создании: " + error.message);
    }
};

let currentContract = null;
const editModal = new bootstrap.Modal(document.getElementById("editContractModal"));
const deleteFileModal = new bootstrap.Modal(document.getElementById("deleteFileModal"));

// Обработчик кнопки удаления договора
document.getElementById("deleteContractButton").addEventListener("click", () => {
    const contractId = document.getElementById("editContractId").value;
    showDeleteModal(contractId);
});

// Обработчик очистки истории
document.getElementById("clearHistoryButton").addEventListener("click", async () => {
    const contractId = document.getElementById("editContractId").value;
    if (!confirm("Вы уверены, что хотите очистить историю действий для договора с ID " + contractId + "?")) {
        return;
    }
    try {
        const response = await fetchWithAuth(`${BASE_URL}/contracts/${contractId}/clear-history`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" }
        });
        if (!response.ok) throw new Error(`Ошибка при очистке истории: ${response.statusText}`);
        document.getElementById("editHistory").value = "История пуста";
        currentContract.history = "";
        alert("История действий успешно очищена!");
    } catch (error) {
        console.error("Ошибка:", error);
        alert("Не удалось очистить историю: " + error.message);
    }
});

// Просмотр файла
async function viewFile(contractId, fileType) {
    try {
        const response = await fetchWithAuth(`${BASE_URL}/download/${contractId}/${fileType}`);
        if (!response.ok) throw new Error(`Ошибка при загрузке файла: ${response.statusText}`);
        const contentType = response.headers.get('Content-Type');
        const textMimeTypes = ['text/plain', 'text/html', 'text/css', 'text/javascript', 'application/json'];
        const docxMimeTypes = [
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/octet-stream'
        ];
        const fileContentElement = document.getElementById('fileContent');
        const viewFileModal = new bootstrap.Modal(document.getElementById('viewFileModal'));
        fileContentElement.innerHTML = '';
        if (contentType && textMimeTypes.some(type => contentType.includes(type))) {
            const text = await response.text();
            fileContentElement.textContent = text;
            viewFileModal.show();
            return;
        }
        if (contentType && docxMimeTypes.some(type => contentType.includes(type))) {
            const arrayBuffer = await response.arrayBuffer();
            const result = await mammoth.convertToHtml({ arrayBuffer: arrayBuffer });
            fileContentElement.innerHTML = result.value;
            viewFileModal.show();
            return;
        }
        alert('Просмотр доступен только для текстовых файлов (например, .txt, .html, .css, .js, .json) или файлов .docx.');
    } catch (error) {
        console.error('Ошибка просмотра:', error);
        alert('Не удалось просмотреть файл: ' + error.message);
    }
}

// Обработчик событий при загрузке DOM
document.addEventListener('DOMContentLoaded', async () => {
    console.log("[DEBUG] DOMContentLoaded сработал");
    const modalDialog = document.querySelector('#viewFileModal .modal-dialog');
    if (modalDialog) {
        const savedWidth = localStorage.getItem('viewFileModalWidth');
        if (savedWidth) {
            modalDialog.style.width = savedWidth;
        }
        modalDialog.addEventListener('resize', () => {
            const currentWidth = modalDialog.offsetWidth + 'px';
            localStorage.setItem('viewFileModalWidth', currentWidth);
        });
    }

    // Инициализация UI в скрытом состоянии
    const mainContent = document.getElementById("mainContent");
    const logoutButton = document.getElementById("logoutButton");
    mainContent.style.display = "none";
    logoutButton.style.display = "none";
    console.log("[DEBUG] UI инициализирован в скрытом состоянии");

    try {
        const isTokenValid = await validateToken();
        if (isTokenValid) {
            document.getElementById("mainContent").style.display = "block";
            document.getElementById("logoutButton").style.display = "inline-block";
            
            // Получаем сохранённые данные
            const fullName = localStorage.getItem("userFullName") || "Неизвестный пользователь";
            const role = localStorage.getItem("userRole");
            
            // Обновляем отображение
            document.getElementById("userInfo").innerText = 
                `Пользователь: ${fullName} (${translateRole(role)})`;
            
            updateUI();
            loadContracts();
        } else {
            mainContent.style.display = "none";
            logoutButton.style.display = "none";
            loginModal.show();
        }
    } catch (error) {
        console.error("[ERROR] Критическая ошибка при загрузке страницы:", error);
        mainContent.style.display = "none";
        logoutButton.style.display = "none";
        loginModal.show();
    }
});

// Показ модального окна редактирования договора
function showEditModal(contract) {
    console.log("[DEBUG] Данные контракта при открытии модального окна:", contract);
    currentContract = contract;
    updateFormWithContractData(contract);
    editModal.show();
}

// Показ модального окна удаления файла
function showDeleteFileModal(contractId, fileType, filePath) {
    document.getElementById("deleteFileName").innerText = formatFilePath(filePath);
    document.getElementById("deleteFileContractId").innerText = contractId;
    document.getElementById("confirmDeleteFile").onclick = async () => {
        try {
            const response = await fetchWithAuth(`${BASE_URL}/delete-file/${contractId}/${fileType}`, {
                method: "DELETE"
            });
            if (!response.ok) throw new Error(`Ошибка при удалении файла: ${response.statusText}`);
            const fieldMap = {
                "file": "file_path",
                "lawyer_edited": "lawyer_edited_file_path",
                "chief_accountant_edited": "chief_accountant_edited_file_path",
                "add_agreement": "add_agreement_path",
                "disagreement_protocol": "disagreement_protocol_path",
                "signed_file": "signed_file_path"
            };
            currentContract[fieldMap[fileType]] = null;
            const pathElement = document.getElementById(`edit${fieldMap[fileType].replace(/_/g, '').replace('path', 'Path')}`);
            const inputElement = document.getElementById(`edit${fieldMap[fileType].replace(/_/g, '').replace('path', '')}`);
            if (inputElement) {
                const viewBtn = inputElement.nextElementSibling;
                const downloadBtn = viewBtn.nextElementSibling;
                const deleteBtn = downloadBtn.nextElementSibling;
                if (viewBtn && downloadBtn && deleteBtn) {
                    pathElement.innerText = "Нет загруженного файла";
                    inputElement.value = "";
                    inputElement.classList.remove("has-file");
                    viewBtn.disabled = true;
                    downloadBtn.disabled = true;
                    deleteBtn.disabled = true;
                }
            }
            deleteFileModal.hide();
            alert("Файл успешно удален!");
        } catch (error) {
            console.error("Ошибка:", error);
            alert("Не удалось удалить файл: " + error.message);
        }
    };
    deleteFileModal.show();
}

// Скачивание файла
async function downloadFile(contractId, fileType) {
    try {
        const response = await fetchWithAuth(`${BASE_URL}/download/${contractId}/${fileType}`);
        if (!response.ok) throw new Error(`Ошибка при скачивании файла: ${response.statusText}`);
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = 'downloaded_file';
        if (contentDisposition) {
            const rfc5987Match = contentDisposition.match(/filename\*=UTF-8''(.+)/);
            if (rfc5987Match && rfc5987Match[1]) {
                filename = decodeURIComponent(rfc5987Match[1]);
            } else {
                const standardMatch = contentDisposition.match(/filename="(.+)"/);
                if (standardMatch && standardMatch[1]) {
                    filename = standardMatch[1];
                }
            }
        } else if (currentContract) {
            const filePaths = {
                'file': currentContract.file_path,
                'lawyer_edited': currentContract.lawyer_edited_file_path,
                'chief_accountant_edited': currentContract.chief_accountant_edited_file_path,
                'add_agreement': currentContract.add_agreement_path,
                'disagreement_protocol': currentContract.disagreement_protocol_path,
                'signed_file': currentContract.signed_file_path
            };
            const filePath = filePaths[fileType];
            if (filePath) filename = filePath.split('\\').pop().split('/').pop();
        }
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Ошибка скачивания:', error);
        alert('Не удалось скачать файл: ' + error.message);
    }
}

// Показ модального окна удаления договора
function showDeleteModal(contractId) {
    document.getElementById("deleteContractId").innerText = contractId;
    deleteModal.show();
    document.getElementById("confirmDelete").onclick = async () => {
        try {
            const response = await fetchWithAuth(`${BASE_URL}/contracts/${contractId}`, {
                method: "DELETE"
            });
            if (!response.ok) throw new Error(`Ошибка удаления договора: ${response.statusText}`);
            alert("Договор успешно удалён!");
            deleteModal.hide();
            loadContracts();
        } catch (error) {
            console.error("Ошибка:", error);
            alert("Произошла ошибка при удалении: " + error.message);
        }
    };
}

const clearHistoryModal = new bootstrap.Modal(document.getElementById("clearHistoryModal"));

// Обработчик кнопки подтверждения очистки истории
document.getElementById("confirmClearHistory").addEventListener("click", async () => {
    const contractId = document.getElementById("editContractId").value;
    try {
        const response = await fetch(`${BASE_URL}/contracts/${contractId}/clear-history`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" }
        });
        if (!response.ok) throw new Error(`Ошибка: ${response.statusText}`);
        document.getElementById("editHistory").value = "История пуста";
        currentContract.history = "";
        clearHistoryModal.hide();
        alert("История действий успешно очищена!");
    } catch (error) {
        console.error("Ошибка:", error);
        alert("Не удалось очистить историю: " + error.message);
    }
});

// Обработчик формы редактирования договора
document.getElementById("editContractForm").onsubmit = async (e) => {
    e.preventDefault();
    const id = document.getElementById("editContractId").value;
    const date = document.getElementById("editDate").value;
    const number = document.getElementById("editNumber").value;
    const name = document.getElementById("editName").value;
    const supplier = document.getElementById("editSupplier").value;
    const status = document.getElementById("editStatus").value;
    const movement = document.getElementById("editMovement").value;
    const file = document.getElementById("editFile").files[0];
    const addAgreement = document.getElementById("editAddAgreement").files[0];
    const disagreementProtocol = document.getElementById("editDisagreementProtocol").files[0];
    const lawyerEditedFile = document.getElementById("editLawyerEditedFile").files[0];
    const chiefAccountantEditedFile = document.getElementById("editChiefAccountantEditedFile").files[0];
    const uploadFolder = getUploadFolder();
    const lawyerStatus = document.getElementById("editLawyerStatus").value;
    const chiefAccountantStatus = document.getElementById("editChiefAccountantStatus").value;
    const counterpartyStatus = document.getElementById("editCounterpartyStatus").value;
    const curator = document.getElementById("editCurator").value;
    const signedFile = document.getElementById("editSignedFile").files[0];
    const isSignedElectronically = document.getElementById("editIsSignedElectronically").checked;
    const formData = new FormData();
    formData.append("date", date);
    formData.append("number", number);
    formData.append("copy", name);
    formData.append("supplier", supplier);
    formData.append("status", status);
    formData.append("movement", movement);
    formData.append("uploadFolder", uploadFolder);
    formData.append("lawyer_status", lawyerStatus);
    formData.append("chief_accountant_status", chiefAccountantStatus);
    formData.append("counterparty_status", counterpartyStatus);
    formData.append("curator", curator);
    if (file) formData.append("file", file);
    if (addAgreement) formData.append("add_agreement", addAgreement);
    if (disagreementProtocol) formData.append("disagreement_protocol", disagreementProtocol);
    if (lawyerEditedFile) formData.append("lawyer_edited_file", lawyerEditedFile);
    if (chiefAccountantEditedFile) formData.append("chief_accountant_edited_file", chiefAccountantEditedFile);
    if (signedFile) formData.append("signed_file", signedFile);
    formData.append("is_signed_electronically", isSignedElectronically.toString());
    let isValid = true;
    let errorMessage = "";
    if (status === "Проверка инициатором" && counterpartyStatus !== "Шаблон предоставлен") {
        isValid = false;
        errorMessage = "Статус договора 'Проверка инициатором' возможен только после предоставления шаблона контрагентом.";
    }
    if (status === "Согласование внутри компании") {
        if (counterpartyStatus !== "Шаблон предоставлен") {
            isValid = false;
            errorMessage = "Согласование внутри компании возможно только после предоставления шаблона контрагентом.";
        }
        if (lawyerStatus === "Ожидает проверки" && chiefAccountantStatus === "Ожидает проверки") {
            isValid = false;
            errorMessage = "Для согласования внутри компании хотя бы один из участников (юрист или главбух) должен начать проверку.";
        }
    }
    if (status === "Согласование с контрагентом") {
        if (lawyerStatus !== "Согласовал" || chiefAccountantStatus !== "Согласовал") {
            isValid = false;
            errorMessage = "Согласование с контрагентом возможно только после согласования юриста и главбуха.";
        }
        if (counterpartyStatus === "Ожидает шаблон" || counterpartyStatus === "Шаблон предоставлен") {
            isValid = false;
            errorMessage = "Инициатор должен подтвердить, что договор передан контрагенту, и контрагент начал проверку.";
        }
    }
    if (status === "Подписание") {
        if (lawyerStatus !== "Согласовал" || chiefAccountantStatus !== "Согласовал" || counterpartyStatus !== "Согласовал") {
            isValid = false;
            errorMessage = "Подписание возможно только после согласования всеми сторонами.";
        }
    }
    if (status === "Исполнение" || status === "Завершен") {
        if (lawyerStatus !== "Согласовал" || chiefAccountantStatus !== "Согласовал" || counterpartyStatus !== "Согласовал") {
            isValid = false;
            errorMessage = "Исполнение или завершение возможно только после согласования всеми сторонами.";
        }
    }
    if (!isValid) {
        alert(errorMessage);
        return;
    }
    if (status === "Завершен") {
        if (!isSignedElectronically && !currentContract.signed_file_path && !signedFile) {
            alert("Для завершения договора необходимо либо прикрепить скан подписанного документа, либо отметить подписание по ЭДО");
            return;
        }
    }
    try {
        const response = await fetchWithAuth(`${BASE_URL}/contracts/${id}`, {
            method: "PUT",
            body: formData
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error("Ошибка при обновлении договора: " + errorText);
        }
        const updatedContract = await response.json();
        currentContract = updatedContract;
        updateFormWithContractData(updatedContract);
        alert("Договор успешно сохранен!");
        loadContracts();
    } catch (error) {
        console.error("Ошибка:", error);
        alert("Произошла ошибка при сохранении: " + error.message);
    }
};

// Обновление формы редактирования данными договора
function updateFormWithContractData(contract) {
    console.log("[DEBUG] Обновление формы с данными:", {
        signed_file_path: contract.signed_file_path,
        is_signed_electronically: contract.is_signed_electronically
    });
    document.getElementById("editContractId").value = contract.id || "";
    document.getElementById("editDate").value = contract.date || "";
    document.getElementById("editNumber").value = contract.number || "";
    document.getElementById("editName").value = contract.name || "";
    document.getElementById("editSupplier").value = contract.supplier || "";
    document.getElementById("editStatus").value = contract.status || "";
    document.getElementById("editMovement").value = contract.movement || "";
    document.getElementById("editLawyerStatus").value = contract.lawyer_status || "Ожидает проверки";
    document.getElementById("editChiefAccountantStatus").value = contract.chief_accountant_status || "Ожидает проверки";
    document.getElementById("editCounterpartyStatus").value = contract.counterparty_status || "Ожидает шаблон";
    document.getElementById("editCurator").value = contract.curator || "";
    const isSignedElectronically = contract.is_signed_electronically === true;
    document.getElementById("editIsSignedElectronically").checked = isSignedElectronically;
    const historyText = contract.history || "История пуста";
    const historyLines = historyText.split("\n").filter(line => line.trim() !== "");
    document.getElementById("editHistory").value = historyLines.join("\n");
    const fileTypes = [
        {id: "editFilePath", path: "file_path", inputId: "editFile", type: "file"},
        {id: "editLawyerEditedFilePath", path: "lawyer_edited_file_path", inputId: "editLawyerEditedFile", type: "lawyer_edited"},
        {id: "editChiefAccountantEditedFilePath", path: "chief_accountant_edited_file_path", inputId: "editChiefAccountantEditedFile", type: "chief_accountant_edited"},
        {id: "editAddAgreementPath", path: "add_agreement_path", inputId: "editAddAgreement", type: "add_agreement"},
        {id: "editDisagreementProtocolPath", path: "disagreement_protocol_path", inputId: "editDisagreementProtocol", type: "disagreement_protocol"},
        {id: "editSignedFilePath", path: "signed_file_path", inputId: "editSignedFile", type: "signed_file"}
    ];
    fileTypes.forEach(file => {
        const pathElement = document.getElementById(file.id);
        const inputElement = document.getElementById(file.inputId);
        if (!inputElement) {
            console.warn(`[WARN] Элемент с ID ${file.inputId} не найден`);
            return;
        }
        let viewBtn = inputElement.nextElementSibling;
        let downloadBtn = viewBtn.nextElementSibling;
        let deleteBtn = downloadBtn.nextElementSibling;
        pathElement.innerText = contract[file.path] ? formatFilePath(contract[file.path]) : "Нет загруженного файла";
        inputElement.value = "";
        const hasFile = !!contract[file.path];
        if (hasFile) {
            inputElement.classList.add("has-file");
        } else {
            inputElement.classList.remove("has-file");
        }
        if (file.inputId === "editSignedFile" && isSignedElectronically) {
            inputElement.disabled = true;
            viewBtn.disabled = true;
            downloadBtn.disabled = true;
            deleteBtn.disabled = true;
        } else {
            inputElement.disabled = false;
            viewBtn.disabled = !hasFile;
            downloadBtn.disabled = !hasFile;
            deleteBtn.disabled = !hasFile;
        }
        viewBtn.onclick = () => viewFile(contract.id, file.type);
        downloadBtn.onclick = () => downloadFile(contract.id, file.type);
        deleteBtn.onclick = () => showDeleteFileModal(contract.id, file.type, contract[file.path]);
    });
}

// Обработчик изменения чекбокса "Подписано по ЭДО"
document.getElementById("editIsSignedElectronically").addEventListener("change", function () {
    const isChecked = this.checked;
    const signedFileInput = document.getElementById("editSignedFile");
    const viewBtn = signedFileInput.nextElementSibling;
    const downloadBtn = viewBtn.nextElementSibling;
    const deleteBtn = downloadBtn.nextElementSibling;
    signedFileInput.disabled = isChecked;
    if (isChecked) {
        viewBtn.disabled = true;
        downloadBtn.disabled = true;
        deleteBtn.disabled = true;
        signedFileInput.classList.remove("has-file");
    } else {
        const hasFile = !!currentContract.signed_file_path;
        viewBtn.disabled = !hasFile;
        downloadBtn.disabled = !hasFile;
        deleteBtn.disabled = !hasFile;
        if (hasFile) {
            signedFileInput.classList.add("has-file");
        } else {
            signedFileInput.classList.remove("has-file");
        }
    }
});

// Обработчик формы настроек
document.getElementById("settingsForm").onsubmit = (e) => {
    e.preventDefault();
    const folderPath = document.getElementById("folderPathInput").value.trim();
    const backendUrl = document.getElementById("backendUrlInput").value.trim();
    if (backendUrl) {
        localStorage.setItem("backendUrl", backendUrl);
        location.reload();
    }
    if (saveUploadFolder(folderPath)) settingsModal.hide();
};

// Инициализация полей настроек
document.getElementById("backendUrlInput").value = BASE_URL;
document.getElementById("selectedFolderPath").innerText = `Текущая папка: ${getUploadFolder()}`;



// Обработчик кнопки управления кураторами
let curatorsModalInstance = null;

document.getElementById("showCuratorsModal").addEventListener("click", () => {
    const modalElement = document.getElementById("curatorsModal");
    curatorsModalInstance = new bootstrap.Modal(modalElement);
    curatorsModalInstance.show();
});

// Обработчик формы добавления пользователя
document.getElementById("addUserForm").onsubmit = async (e) => {
    e.preventDefault();
    const login = document.getElementById("userLogin").value;
    const password = document.getElementById("userPassword").value;
    const role = document.getElementById("userRole").value;
    const surname = document.getElementById("userSurname").value;
    const name = document.getElementById("userName").value;
    const patronymic = document.getElementById("userPatronymic").value;

    try {
        // Проверка уникальности логина
        const checkResponse = await fetchWithAuth(`${BASE_URL}/users/check-login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ login })
        });
        if (!checkResponse.ok) {
            const errorText = await checkResponse.text();
            throw new Error(`Логин уже существует: ${errorText}`);
        }

        const response = await fetchWithAuth(`${BASE_URL}/users`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ login, password, role, surname, name, patronymic })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Ошибка создания пользователя: ${errorText}`);
        }

        showNotificationModal("Пользователь успешно создан!");
        document.getElementById("addUserForm").reset();
        bootstrap.Modal.getInstance(document.getElementById("addUserModal")).hide();
    } catch (error) {
        console.error("Ошибка:", error);
        showNotificationModal("Произошла ошибка при создании пользователя: " + error.message);
    }
};

// Обработчик кнопки закрытия модального окна кураторов
document.querySelector('#curatorsModal .btn-secondary[data-bs-dismiss="modal"]').addEventListener("click", () => {
    console.log("[DEBUG] Нажата кнопка закрытия модального окна кураторов");
    if (curatorsModalInstance) {
        curatorsModalInstance.hide();
        console.log("[DEBUG] Модальное окно кураторов закрыто через JavaScript");
    }
    // Удаляем остаточные оверлеи и сбрасываем стили
    document.querySelectorAll(".modal-backdrop").forEach(backdrop => {
        backdrop.remove();
        console.log("[DEBUG] Удалён остаточный .modal-backdrop");
    });
    document.body.classList.remove("modal-open");
    document.body.style.overflow = "";
    console.log("[DEBUG] Класс modal-open удалён, стиль overflow сброшен");
});

// Загрузка списка пользователей
async function loadUsers() {
    try {
        const response = await fetchWithAuth(`${BASE_URL}/users`);
        if (!response.ok) throw new Error(`Ошибка загрузки пользователей: ${response.statusText}`);
        const users = await response.json();
        
        const usersTable = document.getElementById("usersTable");
        if (!usersTable) {
            console.warn("[WARN] Элемент usersTable не найден");
            return;
        }
        
        usersTable.innerHTML = "";
        users.forEach(user => {
            const row = document.createElement("tr");
            const fullName = `${user.surname} ${user.name} ${user.patronymic}`;
            row.innerHTML = `
                <td>${user.id}</td>
                <td>${user.login}</td>
                <td>${translateRole(user.role)}</td>
                <td>${fullName}</td>
                <td>
                    <button class="btn btn-primary btn-sm edit-user" data-id="${user.id}">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-danger btn-sm delete-user" data-id="${user.id}">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            `;
            usersTable.appendChild(row);
        });

        // Обработчики для кнопок редактирования
        document.querySelectorAll(".edit-user").forEach(btn => {
            btn.addEventListener("click", async () => {
                const userId = btn.dataset.id;
                try {
                    const response = await fetchWithAuth(`${BASE_URL}/users/${userId}`);
                    if (!response.ok) throw new Error(`Ошибка загрузки данных пользователя: ${response.statusText}`);
                    const user = await response.json();
                    
                    // Заполняем форму редактирования
                    document.getElementById("editUserId").value = user.id;
                    document.getElementById("editUserLogin").value = user.login;
                    document.getElementById("editUserRole").value = user.role;
                    document.getElementById("editUserSurname").value = user.surname;
                    document.getElementById("editUserName").value = user.name;
                    document.getElementById("editUserPatronymic").value = user.patronymic;
                    
                    // Показываем модальное окно
                    const editUserModal = new bootstrap.Modal(document.getElementById("editUserModal"));
                    editUserModal.show();
                } catch (error) {
                    console.error("[ERROR] Ошибка при загрузке пользователя:", error);
                    showNotificationModal("Не удалось загрузить данные пользователя: " + error.message);
                }
            });
        });

        // Обработчики для кнопок удаления
        document.querySelectorAll(".delete-user").forEach(btn => {
            btn.addEventListener("click", async () => {
                const userId = btn.dataset.id;
                if (confirm(`Вы уверены, что хотите удалить пользователя с ID ${userId}?`)) {
                    try {
                        const response = await fetchWithAuth(`${BASE_URL}/users/${userId}`, {
                            method: "DELETE"
                        });
                        if (!response.ok) throw new Error(`Ошибка удаления пользователя: ${response.statusText}`);
                        showNotificationModal("Пользователь успешно удалён!");
                        loadUsers(); // Обновляем список
                    } catch (error) {
                        console.error("[ERROR] Ошибка при удалении пользователя:", error);
                        showNotificationModal("Не удалось удалить пользователя: " + error.message);
                    }
                }
            });
        });
    } catch (error) {
        console.error("[ERROR] Ошибка в loadUsers:", error);
        showNotificationModal("Не удалось загрузить список пользователей: " + error.message);
    }
}

// Обработчик формы редактирования пользователя
document.getElementById("editUserForm").onsubmit = async (e) => {
    e.preventDefault();
    const userId = document.getElementById("editUserId").value;
    const updatedUser = {
        login: document.getElementById("editUserLogin").value,
        password: document.getElementById("editUserPassword").value || undefined,
        role: document.getElementById("editUserRole").value,
        surname: document.getElementById("editUserSurname").value,
        name: document.getElementById("editUserName").value,
        patronymic: document.getElementById("editUserPatronymic").value
    };

    try {
        const response = await fetchWithAuth(`${BASE_URL}/users/${userId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(updatedUser)
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Ошибка обновления пользователя: ${errorText}`);
        }
        
        showNotificationModal("Пользователь успешно обновлён!");
        bootstrap.Modal.getInstance(document.getElementById("editUserModal")).hide();
        loadUsers(); // Обновляем список
    } catch (error) {
        console.error("[ERROR] Ошибка при обновлении пользователя:", error);
        showNotificationModal("Не удалось обновить пользователя: " + error.message);
    }
};

// Обработчик кнопки показа модального окна пользователей
document.getElementById("showUsersModal").addEventListener("click", () => {
    loadUsers();
});