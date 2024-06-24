<?php

namespace App\Http\Controllers;

use App\Models\Employee;
use App\Models\Position;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use RealRashid\SweetAlert\Facades\Alert;
use Maatwebsite\Excel\Facades\Excel;
use App\Exports\EmployeesExport;
use Barryvdh\DomPDF\PDF;

class EmployeeController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    // public function index()
    // {
    //     $pageTitle = 'Employee List';
    //     // RAW SQL QUERY
    //     // $employees = DB::select(' select *, employees.id as employee_id, positions.name as position_name from employees left join positions on employees.position_id = positions.id ');
    //     // return view('employee.index', [
    //     //     'pageTitle' => $pageTitle,
    //     //     'employees' => $employees
    //     // ]);

    //     // Query Builder
    //     $employees = DB::table('employees')
    //         ->leftJoin('positions', 'employees.position_id', '=', 'positions.id')
    //         ->select('employees.*', 'employees.id as employee_id', 'positions.name as position_name')
    //         ->get();

    //     return view('employee.index', [
    //         'pageTitle' => $pageTitle,
    //         'employees' => $employees
    //     ]);
    // }

    public function index()
    {
        $pageTitle = 'Employee List';

        confirmDelete();

        $positions = Position::all();
        return view('employee.index', [
            'pageTitle' => $pageTitle,
            'positions' => $positions
        ]);
    }


    /**
     * Show the form for creating a new resource.
     */
    // public function create()
    // {
    //     $pageTitle = 'Create Employee';
    //     // RAW SQL Query
    //     // $positions = DB::select('select * from positions');
    //     // return view('employee.create', compact('pageTitle', 'positions'));

    //     // Query Builder
    //     $positions = DB::table('positions')->get();

    //     return view('employee.create', compact('pageTitle', 'positions'));
    // }


    // /**
    //  * Store a newly created resource in storage.
    //  */
    // public function store(Request $request)
    // {
    //     $messages = [
    //         'required' => ':Attribute harus diisi.',
    //         'email' => 'Isi :attribute dengan format yang benar',
    //         'numeric' => 'Isi :attribute dengan angka'
    //     ];
    //     $validator = Validator::make($request->all(), [
    //         'firstName' => 'required',
    //         'lastName' => 'required',
    //         'email' => 'required|email',
    //         'age' => 'required|numeric',
    //     ], $messages);
    //     if ($validator->fails()) {
    //         return redirect()->back()->withErrors($validator)->withInput();
    //     }
    //     // INSERT QUERY
    //     DB::table('employees')->insert([
    //         'firstname' => $request->firstName,
    //         'lastname' => $request->lastName,
    //         'email' => $request->email,
    //         'age' => $request->age,
    //         'position_id' => $request->position,
    //     ]);

    //     return redirect()->route('employees.index');
    // }

    public function create()
    {
        $pageTitle = 'Create Employee';
        // ELOQUENT
        $positions = Position::all();
        return view('employee.create', compact('pageTitle', 'positions'));
    }
    public function store(Request $request)
    {
        $messages = [
            'required' => ':Attribute harus diisi.',
            'email' => 'Isi :attribute dengan format yang benar',
            'numeric' => 'Isi :attribute dengan angka'
        ];

        $validator = Validator::make($request->all(), [
            'firstName' => 'required',
            'lastName' => 'required',
            'email' => 'required|email',
            'age' => 'required|numeric',
        ], $messages);

        if ($validator->fails()) {
            return redirect()->back()->withErrors($validator)->withInput();
        }

        // Get File
        $file = $request->file('cv');

        if ($file != null) {
            $originalFilename = $file->getClientOriginalName();
            $encryptedFilename = $file->hashName();

            // Store File
            $file->store('public/files');
        }

        // ELOQUENT
        $employee = new Employee;
        $employee->firstname = $request->firstName;
        $employee->lastname = $request->lastName;
        $employee->email = $request->email;
        $employee->age = $request->age;
        $employee->position_id = $request->position;

        if ($file != null) {
            $employee->original_filename = $originalFilename;
            $employee->encrypted_filename = $encryptedFilename;
        }

        $employee->save();

        Alert::success('Added Successfully', 'Employee Data Added Successfully.');

        return redirect()->route('employees.index');
    }

    public function downloadFile($employeeId)
    {
        $employee = Employee::find($employeeId);
        $encryptedFilename = 'public/files/' . $employee->encrypted_filename;
        $downloadFilename = Str::lower($employee->firstname . '_' . $employee->lastname . '_cv.pdf');

        if (Storage::exists($encryptedFilename)) {
            return Storage::download($encryptedFilename, $downloadFilename);
        }
    }

    /**
     * Display the specified resource.
     */
    // public function show(string $id)
    // {
    //     $pageTitle = 'Employee Detail';
    //     // RAW SQL QUERY
    //     // $employee = collect(DB::select(' select *, employees.id as employee_id, positions.name as position_name from employees left join positions on employees.position_id = positions.id where employees.id = ? ', [$id]))->first();
    //     $employee = DB::table('employees')
    //         ->leftJoin('positions', 'employees.position_id', '=', 'positions.id')
    //         ->select('employees.*', 'employees.id as employee_id', 'positions.name as position_name')
    //         ->where('employees.id', $id)
    //         ->first();
    //     return view('employee.show', compact('pageTitle', 'employee'));
    // }

    public function show(string $id)
    {
        $pageTitle = 'Employee Detail';
        // ELOQUENT
        $employee = Employee::find($id);
        return view('employee.show', compact('pageTitle', 'employee'));
    }

    /**
     * Show the form for editing the specified resource.
     */
    // public function edit(string $id)
    // {
    //     $pageTitle = 'Edit Employee';

    //     // $employee = collect(DB::select('select * from employees where id = ?', [$id]))->first();
    //     // $positions = DB::select('select * from positions');

    //     // Query Builder
    //     $employee = DB::table('employees')->where('id', $id)->first();
    //     $positions = DB::table('positions')->get();

    //     return view('employee.edit', compact('pageTitle', 'employee', 'positions'));
    // }


    // /**
    //  * Update the specified resource in storage.
    //  */
    // public function update(Request $request, string $id)
    // {
    //     $messages = [
    //         'required' => ':Attribute harus diisi.',
    //         'email' => 'Isi :attribute dengan format yang benar',
    //         'numeric' => 'Isi :attribute dengan angka'
    //     ];

    //     $validator = Validator::make($request->all(), [
    //         'firstName' => 'required',
    //         'lastName' => 'required',
    //         'email' => 'required|email',
    //         'age' => 'required|numeric',
    //         'position' => 'required'
    //     ], $messages);

    //     if ($validator->fails()) {
    //         return redirect()->back()->withErrors($validator)->withInput();
    //     }

    //     // UPDATE QUERY
    //     DB::table('employees')
    //         ->where('id', $id)
    //         ->update([
    //             'firstname' => $request->firstName,
    //             'lastname' => $request->lastName,
    //             'email' => $request->email,
    //             'age' => $request->age,
    //             'position_id' => $request->position,
    //         ]);

    //     return redirect()->route('employees.index');
    // }

    public function edit(string $id)
    {
        $pageTitle = 'Edit Employee';
        // ELOQUENT
        $positions = Position::all();
        $employee = Employee::find($id);
        return view('employee.edit', compact(
            'pageTitle',
            'positions',
            'employee'
        ));
    }
    public function update(Request $request, string $id)
    {
        $messages = [
            'required' => ':Attribute harus diisi.',
            'email' => 'Isi :attribute dengan format yang benar',
            'numeric' => 'Isi :attribute dengan angka'
        ];

        $validator = Validator::make($request->all(), [
            'firstName' => 'required',
            'lastName' => 'required',
            'email' => 'required|email',
            'age' => 'required|numeric',
        ], $messages);

        if ($validator->fails()) {
            return redirect()->back()->withErrors($validator)->withInput();
        }

        // Get File
        $file = $request->file('cv');

        if ($file != null) {
            $originalFilename = $file->getClientOriginalName();
            $encryptedFilename = $file->hashName();

            // Delete Old File
            $employee = Employee::find($id);
            $oldFile = 'public/files/' . $employee->encrypted_filename;
            if (Storage::exists($oldFile)) {
                Storage::delete($oldFile);
            }

            // Store File
            $file->store('public/files');
        }

        // ELOQUENT
        $employee = Employee::find($id);
        $employee->firstname = $request->firstName;
        $employee->lastname = $request->lastName;
        $employee->email = $request->email;
        $employee->age = $request->age;
        $employee->position_id = $request->position;

        if ($file != null) {
            $employee->original_filename = $originalFilename;
            $employee->encrypted_filename = $encryptedFilename;
        }

        $employee->save();

        Alert::success('Changed Successfully', 'Employee Data Changed Successfully.');

        return redirect()->route('employees.index');
    }


    /**
     * Remove the specified resource from storage.
     */
    // public function destroy(string $id)
    // {
    //     DB::table('employees')
    //         ->where('id', $id)
    //         ->delete();
    //     return redirect()->route('employees.index');
    // }

    public function destroy(string $id)
    {
        // Delete File
        $employee = Employee::find($id);
        $file = 'public/files/' . $employee->encrypted_filename;
        if (Storage::exists($file)) {
            Storage::delete($file);
        }
        // ELOQUENT
        Employee::find($id)->delete();
        Alert::success('Deleted Successfully', 'Employee Data Deleted Successfully.');
        return redirect()->route('employees.index');
    }

    public function getData(Request $request)
    {
        $employees = Employee::with('position');

        if ($request->ajax()) {
            return datatables()->of($employees)
                ->addIndexColumn()
                ->addColumn('actions', function ($employee) {
                    return view('employee.actions', compact('employee'));
                })
                ->toJson();
        }
    }

    public function exportExcel()
    {
        return Excel::download(new EmployeesExport, 'employees.xlsx');
    }

    public function exportPdf()
    {
        $employees = Employee::all();

        $pdf = app('dompdf.wrapper');
        $pdf->loadView('employee.export_pdf', compact('employees'));


        return $pdf->download('employees.pdf');
    }
}
