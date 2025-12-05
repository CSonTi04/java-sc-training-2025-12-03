package employees;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.function.Supplier;

@Service
@RequiredArgsConstructor
public class EmployeesService {

    private final EmployeesRepository repository;

    //visszatérési érték lista esetén lehet szűrni a visszatérési értéket
    //filterObject az aktuális elemre hivatkozik
    //@PostFilter("T(java.lang.Character).isUpperCase(filterObject.name().charAt(0)) or hasRole('ADMIN')")
    public List<EmployeeModel> listEmployees() {
        return repository.findAllResources();
    }

    //visszatérési értékekre is meglehet adni a jogosultságokat
    //pre előre, post, a visszatérési értékkel dolgozik
    @PostAuthorize("T(java.lang.Character).isUpperCase(returnObject[0]) or hasRole('ADMIN')")
    public EmployeeModel findEmployeeById(long id) {
        return toDto(repository.findById(id).orElseThrow(notFountException(id)));
    }

    //itt lehetne validálni is a command-ot, spring security annotációkkal
    //ha a service-rétegben van, akkor minden controller-t, vagy ide áthívő service-t fedünk
    //ide jöhet bármilyen SPEL kifejezés is
    @PreAuthorize("hasRole('ADMIN')")
    public EmployeeModel createEmployee(EmployeeModel command) {
        var employee = new Employee(command.name());
        repository.save(employee);
        return toDto(employee);
    }

    @Transactional
    public EmployeeModel updateEmployee(long id, EmployeeModel command) {
        var employee = repository.findById(id).orElseThrow(notFountException(id));
        employee.setName(command.name());
        return toDto(employee);
    }

    public void deleteEmployee(long id) {
        repository.deleteById(id);
    }

    private EmployeeModel toDto(Employee employee) {
        return new EmployeeModel(employee.getId(), employee.getName());
    }

    private Supplier<EmployeeNotFoundException> notFountException(long id) {
        return () -> new EmployeeNotFoundException("Employee not found with id: %d".formatted(id));
    }

}
